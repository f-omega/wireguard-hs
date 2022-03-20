module System.Network.Wireguard where

import           Control.Exception (throw, bracket, mask)
import           Control.Monad (unless)
import           Control.Monad.IO.Class (MonadIO(..))

import           Crypto.Error (CryptoFailable(..))
import           Crypto.PubKey.Curve25519 (generateSecretKey, toPublic, secretKey)

#ifdef WITH_AESON
import           Control.Applicative ((<|>))
import           Data.Aeson (ToJSON(..), FromJSON(..))
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Base64 as B64
#endif
import           Data.Bits
import           Data.Coerce (coerce)
import qualified Data.ByteArray as BA
#ifdef WITH_HASHABLE
import           Data.Hashable (Hashable)
#endif
import           Data.Maybe (fromMaybe)
import           Data.String (fromString)
import qualified Data.Text as T
import           Data.Time (UTCTime)
import           Data.Proxy (Proxy(..))
import qualified Data.Vector as V.Normal
import qualified Data.Vector.Storable as V
import qualified Data.Vector.Storable.Sized as VS
import           Data.WideWord.Word128 (Word128(..))
import           Data.Word

#ifdef WITH_BEAM
import           Database.Beam
import           Database.Beam.Backend.SQL
import qualified Data.ByteString as BS
#endif

import           GHC.Generics (Generic)

import           Foreign.C.Error
import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Marshal.Alloc (malloc, mallocBytes, free, alloca)
import           Foreign.Ptr
import           Foreign.Storable

import qualified Net.IP as IP
import           Net.IPv4 (IPv4(..), IPv4Range(..))
import           Net.IPv6 (IPv6(..), IPv6Range(..))
import qualified Net.IPv6 as IPv6
import           Network.Socket (SockAddr(..))
import           Network.Socket.Address (SocketAddress(..))

import           System.Clock (TimeSpec(..))
import           System.IO.Unsafe (unsafePerformIO)

#include "wireguard.h"
#include "string.h"

foreign import ccall unsafe "strncpy" c_strncpy :: Ptr CChar -> Ptr CChar -> CInt -> IO (Ptr CChar)

data IPRange
    = IPRange4 !IPv4Range
    | IPRange6 !IPv6Range
      deriving (Show, Eq, Ord)

singleAddrRange :: IP.IP -> IPRange
singleAddrRange =
 IP.case_ (\v4 -> IPRange4 $ IPv4Range v4 32)
          (\v6 -> IPRange6 $ IPv6Range v6 128)

#ifdef WITH_AESON
instance ToJSON IPRange where
    toJSON (IPRange4 x) = toJSON x
    toJSON (IPRange6 x) = toJSON x

instance FromJSON IPRange where
    parseJSON x = fmap IPRange4 (parseJSON x) <|> fmap IPRange6 (parseJSON x)
#endif

-- | Linux network interface status
data LinkStatus
  = LinkStatusUp | LinkStatusDown
    deriving (Show, Eq, Ord)

linkStatus2Text :: LinkStatus -> T.Text
linkStatus2Text LinkStatusUp = "up"
linkStatus2Text LinkStatusDown = "down"

text2LinkStatus :: T.Text -> Maybe LinkStatus
text2LinkStatus "up" = pure LinkStatusUp
text2LinkStatus "down" = pure LinkStatusDown
text2LinkStatus _ = Nothing

#ifdef WITH_AESON
instance ToJSON LinkStatus where
  toJSON = toJSON . linkStatus2Text

instance FromJSON LinkStatus where
  parseJSON p = maybe (fail "Expected 'up' or 'down' for link status")
                      pure =<<
                fmap text2LinkStatus (parseJSON p)
#endif

#ifdef WITH_BEAM
instance HasSqlValueSyntax syntax T.Text => HasSqlValueSyntax syntax LinkStatus where
    sqlValueSyntax = sqlValueSyntax . linkStatus2Text

instance (FromBackendRow be T.Text, BeamSqlBackend be) => FromBackendRow be LinkStatus where
    fromBackendRow = do
      txt <- fromBackendRow
      case text2LinkStatus txt of
        Nothing -> fail "Expected up, down for link status"
        Just ls -> pure ls
#endif

-- | Type-level representation of wireguard key
data KeyType = PublicKey | PrivateKey

class KnownKeyType (ty :: KeyType) where
  keyTypeVal :: Proxy ty -> KeyType
instance KnownKeyType 'PublicKey where
  keyTypeVal _ = PublicKey
instance KnownKeyType 'PrivateKey where
  keyTypeVal _ = PrivateKey

newtype WgKey (ty :: KeyType) = WgKey (VS.Vector 32 Word8)
  deriving newtype (Storable, Eq, Ord)

newtype UnredactedWgKey = UnredactedWgKey (WgKey 'PublicKey)
  deriving newtype (ToJSON, FromJSON, Show, Eq, Ord)

mkSaveableWgKey :: WgKey t -> UnredactedWgKey
mkSaveableWgKey = UnredactedWgKey . unsafeMkPublic

fromSavedWgKey :: UnredactedWgKey -> WgKey t
fromSavedWgKey (UnredactedWgKey (WgKey x)) = WgKey x

#ifdef WITH_HASHABLE
deriving newtype instance Hashable (WgKey 'PublicKey) -- Restrict hashable instance to only public key
#endif

#ifdef WITH_BEAM
instance HasSqlEqualityCheck be BS.ByteString => HasSqlEqualityCheck be (WgKey ty)
#endif

wgEmptyKey :: WgKey a
wgEmptyKey = WgKey (VS.replicate 0)

-- | Convert any 'WgKey' into a public one. This is unsafe, and only used for testing
unsafeMkPublic :: WgKey a -> WgKey 'PublicKey
unsafeMkPublic (WgKey x) = WgKey x

wgKeyToVector :: WgKey a -> V.Normal.Vector Word8
wgKeyToVector (WgKey x) = V.Normal.fromList (VS.toList x)

wgKeyFromVector :: V.Normal.Vector Word8 -> WgKey a
wgKeyFromVector bytes = WgKey . VS.generate $ \(fromEnum -> i) ->
                        case bytes V.Normal.!? i of
                        Nothing -> 0
                        Just x -> x

instance KnownKeyType ty => Show (WgKey ty) where
  show (WgKey x) = case keyTypeVal (Proxy @ty) of
                     PrivateKey -> "<private key>"
                     PublicKey  -> "WgKey (" ++ show x ++ ")"

instance BA.ByteArrayAccess (WgKey ty) where
  length (WgKey v) = VS.length v -- Always 32, but updates if it changes?
  withByteArray (WgKey v) withPtr =
   let (fPtr, _) = V.unsafeToForeignPtr0 (VS.fromSized v)
   in withForeignPtr fPtr (withPtr . castPtr)

#ifdef WITH_AESON
instance KnownKeyType ty => ToJSON (WgKey ty) where
  toJSON (WgKey key) =
    case keyTypeVal (Proxy @ty) of
      PrivateKey -> toJSON (id @T.Text "(redacted)")
      PublicKey  -> toJSON . B64.encodeBase64 . BS.pack . VS.toList $ key

instance FromJSON (WgKey ty) where
  parseJSON x = do
    b64Encoded <- parseJSON x
    let eRes = B64.decodeBase64 (TE.encodeUtf8 b64Encoded)
    case eRes of
      Left  err -> fail ("Could not decode key: " ++ T.unpack err)
      Right key ->
        case VS.toSized (V.fromList (BS.unpack key)) of
          Nothing -> fail ("key is not the right size")
          Just keySized -> pure (WgKey keySized)
#endif

#ifdef WITH_BEAM
instance FromBackendRow be BS.ByteString => FromBackendRow be (WgKey ty) where
   fromBackendRow = do
      bs <- fromBackendRow
      case VS.toSized (V.fromList (BS.unpack bs)) of
        Nothing -> fail "key is not the right size"
        Just keySized -> pure (WgKey keySized)

instance HasSqlValueSyntax syntax BS.ByteString => HasSqlValueSyntax syntax (WgKey ty) where
   sqlValueSyntax (WgKey key) = sqlValueSyntax (BS.pack . V.toList . VS.fromSized $ key)
#endif

newtype WgDeviceFlags = WgDeviceFlags Word32
  deriving (Show, Eq, Ord)
  deriving newtype (Storable, Bits)

instance Semigroup WgDeviceFlags where
    (<>) = coerce ((.|.) :: Word32 -> Word32 -> Word32)

instance Monoid WgDeviceFlags where
    mempty = WgDeviceFlags 0

wgDeviceReplacePeers, wgDeviceHasPrivateKey, wgDeviceHasPublicKey,
  wgDeviceHasListenPort, wgDeviceHasFwMark :: WgDeviceFlags
wgDeviceReplacePeers = WgDeviceFlags (#const WGDEVICE_REPLACE_PEERS)
wgDeviceHasPrivateKey = WgDeviceFlags (#const WGDEVICE_HAS_PRIVATE_KEY)
wgDeviceHasPublicKey = WgDeviceFlags (#const WGDEVICE_HAS_PUBLIC_KEY)
wgDeviceHasListenPort = WgDeviceFlags (#const WGDEVICE_HAS_LISTEN_PORT)
wgDeviceHasFwMark = WgDeviceFlags (#const WGDEVICE_HAS_FWMARK)

data WgDevice
  = WgDevice
  { wgDeviceName    :: T.Text
  , wgDeviceIndex   :: Word32
  , wgDeviceFlags   :: WgDeviceFlags
  , wgDevicePubKey  :: WgKey 'PublicKey
  , wgDevicePrivKey :: WgKey 'PrivateKey
  , wgDeviceFwMark  :: Word32
  , wgDeviceListenPort :: Word16
  , wgDevicePeers   :: [ WgPeer ]
  } deriving Show

foreign import ccall unsafe "ntohl" c_ntohl :: Word32 -> Word32
foreign import ccall unsafe "htonl" c_htonl :: Word32 -> Word32

instance Storable WgDevice where
  sizeOf _ = (#size wg_device)
  alignment _ = alignment (undefined :: Word32)

  peek p = do
    nm <- fromString <$> peekCString ((#ptr wg_device, name) p)
    ix <- (#peek wg_device, ifindex) p
    flags <- (#peek wg_device, flags) p
    pubkey <- (#peek wg_device, public_key) p
    privkey <- (#peek wg_device, private_key) p
    fwmark <- (#peek wg_device, fwmark) p
    listenport <- (#peek wg_device, listen_port) p
    peerPtr <- (#peek wg_device, first_peer) p
    peers <- readWgPeers peerPtr
    pure WgDevice { wgDeviceName = nm
                  , wgDeviceIndex = ix
                  , wgDeviceFlags = flags
                  , wgDevicePubKey = pubkey
                  , wgDevicePrivKey = privkey
                  , wgDeviceFwMark = fwmark
                  , wgDeviceListenPort = listenport
                  , wgDevicePeers = peers }

  poke p d = do
    let ifName = wgDeviceName d
        ifNameStr = T.unpack ifName

    _ <- withCString ifNameStr $ \ifnamePtr ->
         c_strncpy ((#ptr wg_device, name) p) ifnamePtr (#const IFNAMSIZ)

    (#poke wg_device, ifindex) p (wgDeviceIndex d)
    (#poke wg_device, flags)   p (wgDeviceFlags d)
    (#poke wg_device, public_key) p (wgDevicePubKey d)
    (#poke wg_device, private_key) p (wgDevicePrivKey d)
    (#poke wg_device, fwmark) p (wgDeviceFwMark d)
    (#poke wg_device, listen_port) p (wgDeviceListenPort d)

    (firstPeer, lastPeer) <- writeWgPeers (wgDevicePeers d)
    (#poke wg_device, first_peer) p firstPeer
    (#poke wg_device, last_peer)  p lastPeer

newtype WgPeerFlags = WgPeerFlags Word32
  deriving (Show, Eq, Ord)
  deriving newtype (Storable, Bits)
#ifdef WITH_AESON
  deriving newtype (ToJSON, FromJSON)
#endif

instance Semigroup WgPeerFlags where
    (<>) = coerce ((.|.) :: Word32 -> Word32 -> Word32)

instance Monoid WgPeerFlags where
    mempty = WgPeerFlags 0

wgPeerRemoveMe, wgPeerReplaceAllowedIps, wgPeerHasPublicKey,
  wgPeerHasPresharedKey, wgPeerHasPersistentKeepaliveInterval :: WgPeerFlags
wgPeerRemoveMe = WgPeerFlags (#const WGPEER_REMOVE_ME)
wgPeerReplaceAllowedIps = WgPeerFlags (#const WGPEER_REPLACE_ALLOWEDIPS)
wgPeerHasPublicKey = WgPeerFlags (#const WGPEER_HAS_PUBLIC_KEY)
wgPeerHasPresharedKey = WgPeerFlags (#const WGPEER_HAS_PRESHARED_KEY)
wgPeerHasPersistentKeepaliveInterval = WgPeerFlags (#const WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)

newtype WgSockAddr = WgSockAddr { unWgSockAddr :: SockAddr }
    deriving Show

#ifdef WITH_AESON
instance ToJSON WgSockAddr where
    toJSON (WgSockAddr a) = toJSON (show a)

instance FromJSON WgSockAddr where
    parseJSON = error "FromJSON{WgSockAddr}"
#endif

data WgPeer
  = WgPeer
  { wgPeerFlags :: WgPeerFlags
  , wgPeerKey   :: WgKey 'PublicKey
  , wgPeerPsk   :: WgKey 'PublicKey

  , wgPeerEndpoint  :: WgSockAddr

  , wgPeerLastHandshakeTime :: TimeSpec
  , wgPeerRxBytes, wgPeerTxBytes :: Word64
  , wgPeerPersistentKeepaliveInterval :: Word16

  , wgPeerAllowedIPs :: [ IPRange ]
  } deriving (Show, Generic)

-- | Template for adding a new peer
wgNewPeer :: WgPeer
wgNewPeer = WgPeer
          { wgPeerFlags = mempty
          , wgPeerKey   = wgEmptyKey
          , wgPeerPsk   = wgEmptyKey
          , wgPeerEndpoint = WgSockAddr (SockAddrInet 0 0)
          , wgPeerLastHandshakeTime = 0
          , wgPeerRxBytes = 0
          , wgPeerTxBytes = 0
          , wgPeerPersistentKeepaliveInterval = 0
          , wgPeerAllowedIPs = []
          }

readWgPeers :: Ptr WgPeer -> IO [ WgPeer ]
readWgPeers = go pure
  where
    go a peerPtr
      | peerPtr == nullPtr = a []
      | otherwise = do
         peer <- peek peerPtr
         nextPeer <- (#peek wg_peer, next_peer) peerPtr
         go (a . (peer:)) nextPeer

writeWgPeers :: [WgPeer] -> IO (Ptr WgPeer, Ptr WgPeer)
writeWgPeers = go Nothing Nothing
  where
    go !firstPeer !lastPeer peers =
      case peers of
        [] -> pure ( fromMaybe nullPtr firstPeer
                   , fromMaybe nullPtr lastPeer)

        (x:xs) -> do

          peerPtr <- malloc
          poke peerPtr x -- Store current peer
          (#poke wg_peer, next_peer) peerPtr nullPtr

          -- Update previous next pointer
          case lastPeer of
            Nothing -> pure ()
            Just lastPeerPtr ->
              (#poke wg_peer, next_peer) lastPeerPtr peerPtr

          go (Just (fromMaybe peerPtr firstPeer)) (Just peerPtr) xs

readAllowedIps :: Ptr IPRange -> IO [ IPRange ]
readAllowedIps = go pure
  where
    go a ipPtr
      | ipPtr == nullPtr = a []
      | otherwise = do
          family :: Word16 <- (#peek wg_allowedip, family) ipPtr
          addr <-
            case family of
              (#const AF_INET) -> do
                 IPv4 ip4Network <- (#peek wg_allowedip, ip4) ipPtr
                 pure (IP.fromIPv4 $ IPv4 (c_ntohl ip4Network))
              (#const AF_INET6) -> do
                let bytes = (#ptr wg_allowedip, ip6) ipPtr
                [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15] <-
                  mapM (peekElemOff bytes) [0..15]
                pure (IP.fromIPv6 (IPv6.fromOctets a0 a1 a2 a3
                                                   a4 a5 a6 a7
                                                   a8 a9 a10 a11
                                                   a12 a13 a14 a15))
              _ -> fail "Bad IP in WgPeer ip range"
          cidr :: Word8 <- (#peek wg_allowedip, cidr) ipPtr

          nextPtr <- (#peek wg_allowedip, next_allowedip) ipPtr

          let ipr = IP.case_ (\addr -> IPRange4 $ IPv4Range addr cidr)
                             (\addr -> IPRange6 $ IPv6Range addr cidr)
                             addr

          go (a . (ipr :)) nextPtr

bytes64 :: Word64 -> ( Word8, Word8, Word8, Word8
                     , Word8, Word8, Word8, Word8 )
bytes64 a = ( f 56, f 48, f 40, f 32
            , f 24, f 16, f 8, f 0 )
  where
    f l = fromIntegral ((a `shiftR` l) .&. 0xFF)

writeAllowedIps :: [ IPRange ] -> IO (Ptr IPRange, Ptr IPRange)
writeAllowedIps = go Nothing Nothing
  where
    continue !firstIp !lastIp !ipPtr xs = do
      -- Now set the next allowed ip to null
      (#poke wg_allowedip, next_allowedip) ipPtr nullPtr

      case lastIp of
        Nothing -> pure ()
        Just lastIpPtr ->
          (#poke wg_allowedip, next_allowedip) lastIpPtr ipPtr

      go (Just (fromMaybe ipPtr firstIp)) (Just ipPtr) xs

    go !firstIp !lastIp peers =
      case peers of
        [] -> pure ( fromMaybe nullPtr firstIp
                   , fromMaybe nullPtr lastIp )

        (IPRange4 (IPv4Range (IPv4 ip4Network) cidr):xs) -> do
          ipPtr <- mallocBytes (#size wg_allowedip)
          (#poke wg_allowedip, family) ipPtr ((#const AF_INET) :: Word16)

          -- Write ip4 and convert to network byte order
          (#poke wg_allowedip, ip4) ipPtr ip4Network
          networkHost <- (#peek wg_allowedip, ip4) ipPtr
          (#poke wg_allowedip, ip4) ipPtr (c_htonl networkHost)

          (#poke wg_allowedip, cidr) ipPtr (cidr :: Word8)

          continue firstIp lastIp ipPtr xs

        (IPRange6 (IPv6Range (IPv6 (Word128 ipa ipb)) cidr):xs) -> do
          ipPtr <- mallocBytes (#size wg_allowedip)
          (#poke wg_allowedip, family) ipPtr ((#const AF_INET6) :: Word16)

          let (a0, a1, a2, a3, a4, a5, a6, a7) = bytes64 ipa
              (a8, a9, a10, a11, a12, a13, a14, a15) = bytes64 ipb
              bytes = (#ptr wg_allowedip, ip6) ipPtr
          mapM_ (uncurry (pokeElemOff bytes)) (zip [0..] [ a0, a1, a2, a3, a4, a5, a6, a7, a8
                                                         , a9, a10, a11, a12, a13, a14, a15 ])

          (#poke wg_allowedip, cidr) ipPtr (cidr :: Word8)
          continue firstIp lastIp ipPtr xs

instance Storable WgPeer where
  sizeOf _ = (#size wg_peer)
  alignment _ = alignment (undefined :: Word32)

  peek p = do
    flags <- (#peek wg_peer, flags) p
    key   <- (#peek wg_peer, public_key) p
    psk   <- (#peek wg_peer, preshared_key) p
    ep    <- peekSocketAddress ((#ptr wg_peer, endpoint) p)
    lasthstm <- (#peek wg_peer, last_handshake_time) p
    rx    <- (#peek wg_peer, rx_bytes) p
    tx    <- (#peek wg_peer, tx_bytes) p
    pkai  <- (#peek wg_peer, persistent_keepalive_interval) p
    ipsPtr <- (#peek wg_peer, first_allowedip) p
    ips   <- readAllowedIps ipsPtr
    pure WgPeer { wgPeerFlags = flags
                , wgPeerKey   = key
                , wgPeerPsk   = psk
                , wgPeerEndpoint = WgSockAddr ep
                , wgPeerLastHandshakeTime = lasthstm
                , wgPeerRxBytes = rx
                , wgPeerTxBytes = tx
                , wgPeerPersistentKeepaliveInterval = pkai
                , wgPeerAllowedIPs = ips }

  poke p peer = do
    (#poke wg_peer, flags) p (wgPeerFlags peer)
    (#poke wg_peer, public_key) p (wgPeerKey peer)
    (#poke wg_peer, preshared_key) p (wgPeerPsk peer)
    pokeSocketAddress ((#ptr wg_peer, endpoint) p) (unWgSockAddr (wgPeerEndpoint peer))

    -- The following three fields are not strictly necesary...
    (#poke wg_peer, last_handshake_time) p (wgPeerLastHandshakeTime peer)
    (#poke wg_peer, rx_bytes) p (wgPeerRxBytes peer)
    (#poke wg_peer, tx_bytes) p (wgPeerTxBytes peer)

    (#poke wg_peer, persistent_keepalive_interval) p (wgPeerPersistentKeepaliveInterval peer)

    (firstAllowedIp, lastAllowedIp) <- writeAllowedIps (wgPeerAllowedIPs peer)
    (#poke wg_peer, first_allowedip) p firstAllowedIp
    (#poke wg_peer, last_allowedip) p lastAllowedIp

readStringList :: ([String] -> [String]) -> CString -> IO [String]
readStringList a ptr = do
  s <- peekCString ptr
  if null s then pure (a [])
     else do
       readStringList (a . (s:)) (ptr `plusPtr` (length s + 1))

foreign import ccall unsafe "wg_list_device_names" c_wg_list_device_names :: IO CString

wgListDeviceNames :: MonadIO m => m [T.Text]
wgListDeviceNames = liftIO $ do
  devs <- c_wg_list_device_names
  res <- fmap (map fromString) (readStringList id devs)
  free devs

  errno <- getErrno
  if errno == eOK
     then pure res
     else throwErrno "wgListDeviceNames"

foreign import ccall unsafe "wg_get_device" c_wg_get_device :: Ptr (Ptr WgDevice) -> CString -> IO CInt
foreign import ccall unsafe "wg_free_device" c_wg_free_device :: Ptr WgDevice -> IO ()

wgGetDevice :: MonadIO m => T.Text -> m WgDevice
wgGetDevice iface =
  liftIO $
  alloca $ \wgPtrPtr ->
  withCString (T.unpack iface) $ \ifaceStr -> do
    _ <- c_wg_get_device wgPtrPtr ifaceStr
    errno <- getErrno
    if errno == eOK
       then do
         wgPtr <- peek wgPtrPtr
         wg <- peek wgPtr
         c_wg_free_device wgPtr
         pure wg
       else throwErrno "wgGetDevice"

foreign import ccall unsafe "wg_add_device" c_wg_add_device :: Ptr CChar -> IO CInt

wgAddDevice :: MonadIO m => T.Text -> m ()
wgAddDevice iface =
  liftIO $
  withCString (T.unpack iface) $ \ifaceStr -> do
    _ <- c_wg_add_device ifaceStr
    errno <- getErrno
    unless (errno == eOK) (throwErrno "wgAddDevice")

foreign import ccall unsafe "wg_del_device" c_wg_del_device :: Ptr CChar -> IO CInt

wgDelDevice :: MonadIO m => T.Text -> m ()
wgDelDevice iface =
  liftIO $
  withCString (T.unpack iface) $ \ifaceStr -> do
    _ <- c_wg_del_device ifaceStr
    errno <- getErrno
    unless (errno == eOK) (throwErrno "wgDelDevice")

foreign import ccall unsafe "wg_set_device" c_wg_set_device :: Ptr WgDevice -> IO CInt

wgSetDevice :: MonadIO m => WgDevice -> m ()
wgSetDevice dev =
  liftIO $
  bracket (mask $ \_ -> do -- This should not cause any exception...
             wgPtr <- malloc
             poke wgPtr dev
             pure wgPtr)

          c_wg_free_device $ \devPtr -> do
    _ <- c_wg_set_device devPtr
    errno <- getErrno
    unless (errno == eOK) (throwErrno "wgSetDevice");

-- Link status

foreign import ccall unsafe "wg_get_link_status" c_wg_get_link_status :: Ptr CChar -> Ptr CInt -> IO CInt

data LinkFlags
  = LinkFlags
  { lfStatus :: LinkStatus
  } deriving Show

wgGetLinkStatus :: MonadIO m => T.Text -> m LinkFlags
wgGetLinkStatus ifaceNm =
  liftIO $
  withCString (T.unpack ifaceNm) $ \ifaceStr ->
  alloca $ \flagsV -> do
    res <- c_wg_get_link_status ifaceStr flagsV
    if res == 0
      then do
        flags <- peek flagsV
        pure LinkFlags
         { lfStatus = if (flags .&. (#const IFF_UP)) > 0
                      then LinkStatusUp
                      else LinkStatusDown
         }
      else throwErrno "wgGetLinkStatus"

-- | Generate a wireguard private key
wgGeneratePrivateKey :: MonadIO m => m (WgKey 'PrivateKey)
wgGeneratePrivateKey = liftIO $ do
  key <- generateSecretKey
  BA.withByteArray key peek

-- | Derive public key from private one
wgGetPublicKey :: WgKey 'PrivateKey -> WgKey 'PublicKey
wgGetPublicKey key =
  case secretKey key of
    CryptoFailed err -> throw err
    CryptoPassed privKey ->
      unsafePerformIO $ BA.withByteArray (toPublic privKey) peek
