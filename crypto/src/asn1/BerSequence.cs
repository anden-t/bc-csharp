using System;

namespace Org.BouncyCastle.Asn1
{
	public class BerSequence
		: DerSequence
	{
		public static new readonly BerSequence Empty = new BerSequence();

		public static new BerSequence FromVector(Asn1EncodableVector elementVector)
		{
            return elementVector.Count < 1 ? Empty : new BerSequence(elementVector);
		}

		/**
		 * create an empty sequence
		 */
		public BerSequence()
            : base()
		{
		}

		/**
		 * create a sequence containing one object
		 */
		public BerSequence(Asn1Encodable element)
            : base(element)
		{
		}

		public BerSequence(params Asn1Encodable[] elements)
            : base(elements)
		{
		}

		/**
		 * create a sequence containing a vector of objects.
		 */
		public BerSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
		{
		}

        internal BerSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.EncodedLength(encoding, withID);

            int totalLength = withID ? 4 : 3;

            for (int i = 0, count = elements.Length; i < count; ++i)
            {
                Asn1Object asn1Object = elements[i].ToAsn1Object();
                totalLength += asn1Object.EncodedLength(encoding, true);
            }

            return totalLength;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
            if (Asn1OutputStream.EncodingBer != asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            asn1Out.WriteEncodingIL(withID, Asn1Tags.Constructed | Asn1Tags.Sequence, elements);
		}

        internal override DerBitString ToAsn1BitString()
        {
            return new BerBitString(GetConstructedBitStrings());
        }

        internal override DerExternal ToAsn1External()
        {
            // TODO There is currently no BerExternal class (or ToDLObject/ToDerObject)
            //return ((Asn1Sequence)ToDLObject()).ToAsn1External();
            return new DLSequence(elements).ToAsn1External();
        }

        internal override Asn1OctetString ToAsn1OctetString()
        {
            return new BerOctetString(GetConstructedOctetStrings());
        }

        internal override Asn1Set ToAsn1Set()
        {
            return new BerSet(false, elements);
        }
    }
}
