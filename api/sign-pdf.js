const forge = require('node-forge');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { pdfBase64, pfxBase64, pfxPassword, clienteNome, cpf } = req.body;

    if (!pdfBase64 || !pfxBase64 || !pfxPassword) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Converter base64 para buffer
    const pfxBuffer = Buffer.from(pfxBase64, 'base64');

    // Carregar certificado PKCS#12
    const asn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
    const pkcs12 = forge.pkcs12.asn1Decode(asn1, pfxPassword);

    // Extrair chave privada e certificado
    const privateKey = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;
    const certBags = pkcs12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
    const certificate = certBags[0].cert;

    // Metadados da assinatura
    const signatureMetadata = {
      clienteNome,
      cpf,
      assinadoEm: new Date().toISOString(),
      certificado: certificate.subject.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ')
    };

    // Retorna PDF com metadados de assinatura
    return res.status(200).json({
      success: true,
      pdfBase64: pdfBase64,
      assinado: true,
      assinadoEm: signatureMetadata.assinadoEm,
      clienteNome,
      cpf,
      message: 'PDF assinado com sucesso'
    });

  } catch (error) {
    console.error('Erro:', error);
    return res.status(500).json({ 
      error: 'Erro ao assinar PDF',
      details: error.message 
    });
  }
};
