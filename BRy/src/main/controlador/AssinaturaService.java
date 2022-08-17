package main.controlador;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class AssinaturaService {

	public static String assinador(InputStream file, InputStream pfx, String alias, String senha) {
		
		try {
			//início do processo de assinatura
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			char[] charArray = senha.toCharArray();
			keyStore.load(pfx, charArray);
		
			//retirada do certificado (ou chave publica)	
			List<X509Certificate> listaCertificados = new ArrayList<X509Certificate>(); 
			String aliasMaiusculo = alias.toUpperCase();
			X509Certificate certificado = (X509Certificate) keyStore.getCertificate(aliasMaiusculo);
			listaCertificados.add(certificado);
			JcaCertStore certificadosBC = new JcaCertStore(listaCertificados);
			
			//retirada da chave privada
			PrivateKey chavePrivada = (PrivateKey) keyStore.getKey(alias, charArray);
			
			//processamento da mensagem em byteArray
			byte[] mensagemAssinar = IOUtils.toByteArray(file);
			CMSTypedData arrayProcessado = new CMSProcessableByteArray(mensagemAssinar);
			
			//criando o assinador digital da bouncy
			CMSSignedDataGenerator gerador = new CMSSignedDataGenerator();
			ContentSigner assinadorSHA512 = new JcaContentSignerBuilder("SHA512withRSA").setProvider("BC").build(chavePrivada);
			gerador.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(assinadorSHA512, certificado));
			
			//adiciona um certificado
			gerador.addCertificates(certificadosBC);

			//assinando digitalmente (gera assinatura digital)
			CMSSignedData assinaturaDigital = gerador.generate(arrayProcessado, false);

			//Parece que funcionou, mas o getEncoded já não retorna um byte[]? Parece redundante mas de outra forma não funciona
			byte[] bytesResultado = (byte[]) assinaturaDigital.getEncoded();

			//para encodar em base64 o resultado
	        String conteudo = Base64.getEncoder().encodeToString(bytesResultado);

			
			/*após endpoint, comentar essa parte
	        System.out.println("Conteúdo: " + conteudo + "\n"); 
	        //salvar em .p7s
			String arquivoAssinado = "teste.p7s";
			FileOutputStream assinatura = new FileOutputStream(arquivoAssinado);
			assinatura.write(assinaturaDigital.getEncoded());
			assinatura.close();
			*/
	        
	        return conteudo;
	        
		} catch (KeyStoreException e) {
			return "Erro ao instanciar keystore.";
		} catch (NoSuchAlgorithmException e) {
			return "Algoritmo do certificado é inválido.";
		} catch (CertificateException e) {
			return "O certificado informado é inválido.";
		} catch (IOException e) {
			e.printStackTrace();
			return "Erro na leitura do arquivo de certificado.";
		} catch (UnrecoverableKeyException e) {
			return "Chave do certificado é irrecuperável.";
		} catch (OperatorCreationException e) {
			return "Erro ao instanciar o assinador com os parâmetros informados.";
		} catch (CMSException e) {
			return "Erro ao inicializar assinatura CMS.";
		}
	}
	
	
	
	public static boolean verificaArquivoAssinado(InputStream arquivo, InputStream assinatura) throws FileNotFoundException {
		
		boolean resultado = false;
		
		//instanciando arquivo original
		byte[] bytesDoc = null;
		try {
			bytesDoc = IOUtils.toByteArray(arquivo);
		} catch (IOException e) {
			System.out.println("Falha ao ler documento original.");
			return resultado;
		} 
		
		//instanciando assinatura	
		byte[] bytesAss = null;
		try {
			bytesAss = IOUtils.toByteArray(assinatura);
		} catch (IOException e2) {
			System.out.println("Falha na leitura da assinatura.");
			return resultado;
		} 
		
		Security.addProvider(new BouncyCastleProvider());
		
		//instanciando byte array processado
		CMSSignedData dadosCMS = null;
		CMSProcessableByteArray byteArrayProcessado = new CMSProcessableByteArray(bytesDoc);
		try {
			dadosCMS = new CMSSignedData(byteArrayProcessado, bytesAss);
		} catch (CMSException e) {
			System.out.println("Falha na verificacao do arquivo ou da assinatura.");
			return resultado;
		}

		//pegando certificados da assinatura
		Store<X509CertificateHolder> armazena = dadosCMS.getCertificates();
		
		//pegando assinantes
		SignerInformationStore assinante = dadosCMS.getSignerInfos();
		Collection colAssinante = assinante.getSigners();
		Iterator linkedList = colAssinante.iterator();
		
		//percorrendo toda a lista de assinantes
		while (linkedList.hasNext()) {
			SignerInformation signatario = (SignerInformation) linkedList.next();
			Collection colCertificados = ((CollectionStore) armazena).getMatches(signatario.getSID());
			Iterator linkedListCert = colCertificados.iterator();
			X509CertificateHolder responsavelCertificado = (X509CertificateHolder) linkedListCert.next();
			X509Certificate certificado = null;
			try {
				certificado = new JcaX509CertificateConverter().setProvider("BC").getCertificate(responsavelCertificado);
			} catch (CertificateException e1) {
				System.out.println(
						"Erro ao ler o certificado.");
				return resultado;
			}
			
			//agora verificaremos a assinatura
			try {
				SignerInformationVerifier verificador = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificado);
				if (signatario.verify(verificador)) {
					//caso válida
					resultado = true;
					System.out.println("Válida.");
					return resultado;
				} else {
					//caso inválida
					System.out.println("Inválida.");
					return resultado;
				}
			} catch (OperatorCreationException e) {
				System.out.println("Erro ao instanciar verificador de assinatura.");
			} catch (CMSException e) {
				System.out.println("Erro ao processar assinatura CMS.");
			}
		}
		
		return resultado;
		
	}
	
}
