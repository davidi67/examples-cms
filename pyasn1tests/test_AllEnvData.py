#
# This file is adapted from example code modules `test_rfc*.py` in
# pyasn1-alt-modules software.
#
# Original code by Russ Housley.
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
# Modified by David Ireland for specific tests on known file.
# Copyright (c) 2024, CryptoSys, Australia
#

# Check all enveloped-data objects in `binary-files`

import sys
import unittest

from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
# from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc8017
from pyasn1_alt_modules import opentypemap

# Debugging stuff
DEBUG = False  # Set to True to show debugging output
DPRINT = print if DEBUG else lambda *a, **k: None

testfiles = (
    "../binary-files/encryptedForBobRSAOaep.p7m",
    "../binary-files/encryptedForBobAndDana.p7m",
    "../binary-files/encryptedKekri.p7m",
)


class EnvelopedDataTestCase(unittest.TestCase):

    def readInput(self, inputfile):
        with open(inputfile, "rb") as f:
            return f.read()

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def do_testDerCodec(self, inputfile):
        # Check we have ContentInfo and nothing else
        substrate = self.readInput(inputfile)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        # Validate, re-encode and check against original binary
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        # Check we have enveloped-data type
        self.assertEqual(rfc5652.id_envelopedData, asn1Object['contentType'])
        # Check we can read the signed-data content
        sd, rest = der_decoder(asn1Object['content'],
            asn1Spec=rfc5652.EnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(sd.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(sd))
       
    def do_testOpenTypes(self, inputfile):
        substrate = self.readInput(inputfile)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

        self.assertIn(asn1Object['contentType'], cmsContentTypesMap)
        self.assertEqual(rfc5652.id_envelopedData, asn1Object['contentType'])

        sd = asn1Object['content']

        # Expecting eContentType id_data
        # ect = sd['encapContentInfo']['eContentType']
        # self.assertIn(ect, cmsContentTypesMap)
        # self.assertEqual(rfc5652.id_data, ect)

    def testDoAll(self):
        print()
        for file in testfiles:
            print("About to test '" + file + "'")
            with self.subTest(file=file):
                self.do_testDerCodec(file)
                self.do_testOpenTypes(file)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
