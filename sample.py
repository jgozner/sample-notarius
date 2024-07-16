import os
from dotenv import load_dotenv
from apryse_sdk import *  # type: ignore
from notarius_factory import NotariusFactory

from custom_signing import CustomSigning
load_dotenv()

PDFNet.Initialize(os.environ.get("APRYSE_KEY"))  # type: ignore

pdf_in = "letter.pdf"
pdf_out = "signed.pdf"

def sign_pdf_with_notarius(
    pdf_in=pdf_in,
    in_cert_field_name="BlueinkSignature",
    pdf_out=pdf_out,
):
    notarius_factory = NotariusFactory()

    doc = PDFDoc(pdf_in)
    doc.InitSecurityHandler()
    
    found_approval_field = doc.GetField(in_cert_field_name)
    
    is_locked = (
		True
		if found_approval_field
		and found_approval_field.IsLockedByDigitalSignature()
		else False
	)
    
    if is_locked:
        print("The signature field is locked by a digital signature.")
        raise Exception(f"The signature field is locked by a digital signature.")
    
    page1 = doc.GetPage(1)
    
    certification_sign_field = doc.CreateDigitalSignatureField(in_cert_field_name)
    widgetAnnot = SignatureWidget.Create(doc, Rect(0, 0, 0, 0), certification_sign_field)
    
    page1.AnnotPushBack(widgetAnnot)
    
    certification_sign_field.CreateSigDictForCustomSigning("Adobe.PPKLite", DigitalSignatureField.e_ETSI_CAdES_detached, 7500)
    
    current_date = Date()
    current_date.SetCurrentTime()
    
    certification_sign_field.SetSigDictTimeOfSigning(current_date)
    certification_sign_field.SetLocation("Vancouver, BC")
    certification_sign_field.SetReason("Document certification.")
    certification_sign_field.SetContactInfo("www.blueink.com")
    
    doc.Save(pdf_out, SDFDoc.e_incremental)
    #-----------------------------------------------------------

    signer_cert = notarius_factory.get_signer_cert()
    
    chain_certs = notarius_factory.get_chain_certs()
    
    signer_cert_x509 = X509Certificate(signer_cert)
    
    chain_certs_x509 = [X509Certificate(cert) for cert in chain_certs]
    
    #signing_doc = custom_signing.enable_LTV(signing_doc, signer_cert=signer_cert)

    pdf_digest = certification_sign_field.CalculateDigest(DigestAlgorithm.e_SHA256)
    
    in_digest_algorithm_type = DigestAlgorithm.e_SHA256
    pades_versioned_ess_signing_cert_attribute = (
        DigitalSignatureField.GenerateESSSigningCertPAdESAttribute(
            signer_cert_x509, in_digest_algorithm_type
        )
    )
    signed_attrs = DigitalSignatureField.GenerateCMSSignedAttributes(
        pdf_digest, pades_versioned_ess_signing_cert_attribute
    )
    # signed_attrs = DigitalSignatureField.GenerateCMSSignedAttributes(pdf_digest)
    signed_attrs_digest = DigestAlgorithm.CalculateDigest(
        in_digest_algorithm_type, signed_attrs
    )
    rsa_sign_result = notarius_factory.get_rsa_sign_result(
        bytes(signed_attrs_digest)
    )

    digest_algorithm_oid = ObjectIdentifier(ObjectIdentifier.e_SHA256)
    signature_algorithm_oid = ObjectIdentifier(
        ObjectIdentifier.e_RSA_encryption_PKCS1
    )

    signature = DigitalSignatureField.GenerateCMSSignature(
        signer_cert_x509,
        chain_certs_x509,
        digest_algorithm_oid,
        signature_algorithm_oid,
        rsa_sign_result,
        signed_attrs,
    )

    doc.SaveCustomSignature(signature, certification_sign_field, pdf_out)

    return None


sign_pdf_with_notarius()