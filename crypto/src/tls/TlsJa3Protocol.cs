using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public class TlsJa3Protocol
        : TlsClientProtocol
    {
        public int[] ExtensionsOrder { get; set; }

        /// <summary>Constructor for non-blocking mode.</summary>
        /// <remarks>
        /// When data is received, use <see cref="TlsProtocol.OfferInput(byte[])"/> to provide the received ciphertext,
        /// then use <see cref="TlsProtocol.ReadInput(byte[],int,int)"/> to read the corresponding cleartext.<br/><br/>
        /// Similarly, when data needs to be sent, use <see cref="TlsProtocol.WriteApplicationData(byte[],int,int)"/>
        /// to provide the cleartext, then use <see cref="TlsProtocol.ReadOutput(byte[],int,int)"/> to get the
        /// corresponding ciphertext.
        /// </remarks>
        public TlsJa3Protocol(int[] extensionsOrder)
            : base()
        {
            ExtensionsOrder = extensionsOrder;
        }

        /// <summary>Constructor for blocking mode.</summary>
        /// <param name="stream">The <see cref="Stream"/> of data to/from the server.</param>
        /// <param name="extensionsOrder">TLS Extensions order</param>
        public TlsJa3Protocol(Stream stream, int[] extensionsOrder)
            : base(stream)
        {
            ExtensionsOrder = extensionsOrder;
        }

        /// <summary>Constructor for blocking mode.</summary>
        /// <param name="input">The <see cref="Stream"/> of data from the server.</param>
        /// <param name="output">The <see cref="Stream"/> of data to the server.</param>
        public TlsJa3Protocol(Stream input, Stream output, int[] extensionsOrder)
            : base(input, output)
        {
            ExtensionsOrder = extensionsOrder;
        }

        protected IDictionary<int, byte[]> MakeKeyOrderDictionary(IDictionary<int, byte[]> items)
        {
            IDictionary<int, byte[]> dictionary = TlsExtensionsUtilities.EnsureExtensionsInitialised(null);

            for (int i = 0; i < ExtensionsOrder.Length; i++)
            {
                if (items.ContainsKey(ExtensionsOrder[i]))
                {
                    dictionary[ExtensionsOrder[i]] = items[ExtensionsOrder[i]];
                }
            }

            return dictionary;
        }

        protected override void SendClientHello()
        {
            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            ProtocolVersion[] supportedVersions;
            ProtocolVersion earliestVersion, latestVersion;

            // NOT renegotiating
            {
                supportedVersions = m_tlsClient.GetProtocolVersions();

                if (ProtocolVersion.Contains(supportedVersions, ProtocolVersion.SSLv3))
                {
                    // TODO[tls13] Prevent offering SSLv3 AND TLSv13?
                    m_recordStream.SetWriteVersion(ProtocolVersion.SSLv3);
                }
                else
                {
                    m_recordStream.SetWriteVersion(ProtocolVersion.TLSv10);
                }

                earliestVersion = ProtocolVersion.GetEarliestTls(supportedVersions);
                latestVersion = ProtocolVersion.GetLatestTls(supportedVersions);

                if (!ProtocolVersion.IsSupportedTlsVersionClient(latestVersion))
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                m_tlsClientContext.SetClientVersion(latestVersion);
            }

            m_tlsClientContext.SetClientSupportedVersions(supportedVersions);

            bool offeringTlsV12Minus = ProtocolVersion.TLSv12.IsEqualOrLaterVersionOf(earliestVersion);
            bool offeringTlsV13Plus = ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(latestVersion);

            {
                bool useGmtUnixTime = !offeringTlsV13Plus && m_tlsClient.ShouldUseGmtUnixTime();

                securityParameters.m_clientRandom = CreateRandomBlock(useGmtUnixTime, m_tlsClientContext);
            }

            EstablishSession(offeringTlsV12Minus ? m_tlsClient.GetSessionToResume() : null);
            m_tlsClient.NotifySessionToResume(m_tlsSession);

            /*
             * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
             * Session ID in the TLS ClientHello.
             */
            byte[] legacy_session_id = TlsUtilities.GetSessionID(m_tlsSession);

            bool fallback = m_tlsClient.IsFallback();

            int[] offeredCipherSuites = m_tlsClient.GetCipherSuites();

            if (legacy_session_id.Length > 0 && m_sessionParameters != null)
            {
                if (!Arrays.Contains(offeredCipherSuites, m_sessionParameters.CipherSuite))
                {
                    legacy_session_id = TlsUtilities.EmptyBytes;
                }
            }

            this.m_clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(
                m_tlsClient.GetClientExtensions());

            ProtocolVersion legacy_version = latestVersion;
            if (offeringTlsV13Plus)
            {
                legacy_version = ProtocolVersion.TLSv12;

                TlsExtensionsUtilities.AddSupportedVersionsExtensionClient(m_clientExtensions, supportedVersions);

                /*
                 * RFC 8446 4.2.1. In compatibility mode [..], this field MUST be non-empty, so a client
                 * not offering a pre-TLS 1.3 session MUST generate a new 32-byte value.
                 */
                if (legacy_session_id.Length < 1)
                {
                    legacy_session_id = m_tlsClientContext.NonceGenerator.GenerateNonce(32);
                }
            }

            m_tlsClientContext.SetRsaPreMasterSecretVersion(legacy_version);

            securityParameters.m_clientServerNames = TlsExtensionsUtilities.GetServerNameExtensionClient(
                m_clientExtensions);

            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(latestVersion))
            {
                TlsUtilities.EstablishClientSigAlgs(securityParameters, m_clientExtensions);
            }

            securityParameters.m_clientSupportedGroups = TlsExtensionsUtilities.GetSupportedGroupsExtension(
                m_clientExtensions);

            this.m_clientBinders = TlsUtilities.AddPreSharedKeyToClientHello(m_tlsClientContext, m_tlsClient,
                m_clientExtensions, offeredCipherSuites);

            // TODO[tls13-psk] Perhaps don't add key_share if external PSK(s) offered and 'psk_dhe_ke' not offered  
            this.m_clientAgreements = TlsUtilities.AddKeyShareToClientHello(m_tlsClientContext, m_tlsClient,
                m_clientExtensions);

            if (TlsUtilities.IsExtendedMasterSecretOptionalTls(supportedVersions)
                && (m_tlsClient.ShouldUseExtendedMasterSecret() ||
                    (null != m_sessionParameters && m_sessionParameters.IsExtendedMasterSecret)))
            {
                TlsExtensionsUtilities.AddExtendedMasterSecretExtension(m_clientExtensions);
            }
            else if (!offeringTlsV13Plus && m_tlsClient.RequiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // NOT renegotiating
            {
                /*
                 * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
                 */

                /*
                 * The client MUST include either an empty "renegotiation_info" extension, or the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the ClientHello.
                 * Including both is NOT RECOMMENDED.
                 */
                bool noRenegExt = (null == TlsUtilities.GetExtensionData(m_clientExtensions,
                    ExtensionType.renegotiation_info));
                bool noRenegScsv = !Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

                if (noRenegExt && noRenegScsv)
                {
                    // TODO[tls13] Probably want to not add this if no pre-TLSv13 versions offered?
                    offeredCipherSuites = Arrays.Append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                }
            }

            /*
             * (Fallback SCSV)
             * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
             * than the latest (highest-valued) version supported by the client, it SHOULD include
             * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
             * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
             * to negotiate.)
             */
            if (fallback && !Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
            {
                offeredCipherSuites = Arrays.Append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
            }

            int bindersSize = null == m_clientBinders ? 0 : m_clientBinders.m_bindersSize;

            m_clientExtensions = MakeKeyOrderDictionary(m_clientExtensions);

            this.m_clientHello = new ClientHello(legacy_version, securityParameters.ClientRandom, legacy_session_id,
                null, offeredCipherSuites, m_clientExtensions, bindersSize, true);

            SendClientHelloMessage();
        }
    }
}
