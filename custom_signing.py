import base64
import os
from dotenv import load_dotenv
from apryse_sdk import *  # type: ignore
load_dotenv()
class CustomSigning:
    def __init__(self, pdf_out: str = None):
        self.certification_sign_field = None
        self.pdf_out = pdf_out
        PDFNet.Initialize(os.environ.get("APRYSE_KEY"))  # type: ignore

    def prepare_pdf_custom_signing(
        self, doc, signature_field_name: str, content_size: int = 7500
    ):
        """
        Prepares a PDF for custom signing.

        Args:
            doc (PDFDoc): The PDF document to be signed.
            signature_field_name (str): The name of the signature field.
            pdf_out (str, optional): The output path for the signed PDF. Defaults to None.
            content_size (int, optional): The size of the content to be signed. Defaults to 7500.

        Returns:
            PDFDoc: The signed PDF document.
        """
        found_approval_field = doc.GetField(signature_field_name)
        is_locked = (
            True
            if found_approval_field
            and found_approval_field.IsLockedByDigitalSignature()
            else False
        )

        if is_locked:
            print("The signature field is locked by a digital signature.")
            raise Exception(
                f"The signature field is locked by a digital signature."
            )

        page1 = doc.GetPage(1)
        self.certification_sign_field = doc.CreateDigitalSignatureField(
            signature_field_name
        )
        widgetAnnot = SignatureWidget.Create(doc, Rect(0, 0, 0, 0), self.certification_sign_field)  # type: ignore
        page1.AnnotPushBack(widgetAnnot)

        self.certification_sign_field.CreateSigDictForCustomSigning(
            "Adobe.PPKLite", DigitalSignatureField.e_ETSI_CAdES_detached, content_size
        )
        self.set_certification_sign_field()

        doc.Save(self.pdf_out, SDFDoc.e_incremental)

        return doc

    def set_certification_sign_field(self) -> None:
        current_date = Date()  # type: ignore
        current_date.SetCurrentTime()
        self.certification_sign_field.SetSigDictTimeOfSigning(current_date)
        self.certification_sign_field.SetLocation("Vancouver, BC")
        self.certification_sign_field.SetReason("Document certification.")
        self.certification_sign_field.SetContactInfo("www.blueink.com")

    def get_digital_signature_field(self):
        return self.certification_sign_field

    def get_pdf_digest(self, digest_algorithm: str = DigestAlgorithm.e_SHA256):
        return self.certification_sign_field.CalculateDigest(digest_algorithm)

    def save_pdf_with_digital_signature(
        self, doc, signature_field_name: str, pkcs7message
    ):
        certification_field = doc.GetField(signature_field_name)
        certification_sign_field = DigitalSignatureField(certification_field)

        doc.SaveCustomSignature(pkcs7message, certification_sign_field, self.pdf_out)

    def create_X509Certificate(self, certificate: bytes):
        x509_certificate = X509Certificate(certificate)

        return x509_certificate, [x509_certificate]

    def embedded_timestamp(self, doc, pdf_out):
        tst_config = TimestampingConfiguration("in_timestamp_authority_url")
        opts = VerificationOptions(VerificationOptions.e_compatibility_and_archiving)
        opts.AddTrustedCertificate("in_timestamp_authority_root_certificate_path")
        opts.EnableOnlineCRLRevocationChecking(True)
        result = self.digsig_field.GenerateContentsWithEmbeddedTimestamp(
            tst_config, opts
        )

        if not result.GetStatus():
            print(result.GetString())
            assert False
        doc.SaveCustomSignature(
            result.GetData(), self.certification_sign_field, pdf_out
        )

    def enable_LTV(self, doc, signer_cert):
        opts = VerificationOptions(VerificationOptions.e_compatibility_and_archiving)
        cert = base64.b64encode(signer_cert)
        opts.AddTrustedCertificate(bytearray(cert), len(bytearray(cert)))

        # By default, we only check online for revocation of certificates using the newer and lighter
        # OCSP protocol as opposed to CRL, due to lower resource usage and greater reliability. However,
        # it may be necessary to enable online CRL revocation checking in order to verify some timestamps
        # (i.e. those that do not have an OCSP responder URL for all non-trusted certificates).
        opts.EnableOnlineCRLRevocationChecking(True)
        verification_results = self.certification_sign_field.Verify(opts)
        print(
            f"________________________\n"
            + f"DigestStatus: {verification_results.GetDigestStatusAsString()}\n"
            + f"DigestAlgorithm: {verification_results.GetDigestAlgorithm()}\n"
            + f"DocumentStatus: {verification_results.GetDocumentStatusAsString()}\n"
            + f"TrustStatus: {verification_results.GetTrustStatusAsString()}\n"
            + f"Permission: {verification_results.GetPermissionsStatusAsString()}\n"
        )

        doc.Save(self.pdf_out, SDFDoc.e_incremental)

        return doc

    def debug_verify(self):
        in_opts = VerificationOptions(0)
        digita_signature_field = self.get_digital_signature_field()
        verification_results = digita_signature_field.Verify(in_opts)
        print(
            f"=================================\n"
            + f"DigestStatus: {verification_results.GetDigestStatusAsString()}\n"
            + f"DigestAlgorithm: {verification_results.GetDigestAlgorithm()}\n"
            + f"DocumentStatus: {verification_results.GetDocumentStatusAsString()}\n"
            + f"TrustStatus: {verification_results.GetTrustStatusAsString()}\n"
            + f"Permission: {verification_results.GetPermissionsStatusAsString()}\n"
        )
