using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class LazyDLSet
        : DLSet
    {
        private byte[] encoded;

        internal LazyDLSet(byte[] encoded)
            : base()
        {
            if (null == encoded)
                throw new ArgumentNullException("encoded");

            this.encoded = encoded;
        }

        public override Asn1Encodable this[int index]
        {
            get
            {
                Force();

                return base[index];
            }
        }

        public override IEnumerator GetEnumerator()
        {
            byte[] encoded = GetContents();
            if (null != encoded)
            {
                return new LazyDLEnumerator(encoded);
            }

            return base.GetEnumerator();
        }

        public override int Count
        {
            get
            {
                Force();

                return base.Count;
            }
        }

        public override Asn1Encodable[] ToArray()
        {
            Force();

            return base.ToArray();
        }

        public override string ToString()
        {
            Force();

            return base.ToString();
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingBer == encoding)
            {
                byte[] encoded = GetContents();
                if (null != encoded)
                    return Asn1OutputStream.GetLengthOfEncodingDL(withID, encoded.Length);
            }
            else
            {
                Force();
            }

            return base.EncodedLength(encoding, withID);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Asn1OutputStream.EncodingBer == asn1Out.Encoding)
            {
                byte[] encoded = GetContents();
                if (encoded != null)
                {
                    asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, encoded);
                    return;
                }
            }
            else
            {
                Force();
            }

            base.Encode(asn1Out, withID);
        }

        private void Force()
        {
            lock (this)
            {
                if (null != encoded)
                {
                    Asn1InputStream input = new LazyAsn1InputStream(encoded);
                    try
                    {
                        Asn1EncodableVector v = input.ReadVector();

                        this.elements = v.TakeElements();
                        this.isSorted = elements.Length < 2;
                        this.encoded = null;
                    }
                    catch (IOException e)
                    {
                        throw new Asn1ParsingException("malformed ASN.1: " + e.Message, e);
                    }
                }
            }
        }

        private byte[] GetContents()
        {
            lock (this) return encoded;
        }
    }
}
