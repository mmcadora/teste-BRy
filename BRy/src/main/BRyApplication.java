package main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
//@ComponentScan(basePackageClasses = BRyApplication.class) //Estava dando problema
public class BRyApplication {

	public static void main(String[] args) throws FileNotFoundException {		
		/*File arquivoOriginal = new File("C:\\Users\\Cadora\\Desktop\\BRy\\src\\main\\resources\\arquivos\\doc.txt");
		File certificado = new File("C:\\Users\\Cadora\\Desktop\\BRy\\src\\main\\resources\\arquivos\\certificado_teste_hub.pfx");
		try {			//InputStream ou FileInputStream? 
			 *String resultado = AssinaturaService.assinador(new FileInputStream (arquivoOriginal), new FileInputStream (certificado), "{e2618a8b-20de-4dd2-b209-70912e3177f4}", "bry123456");
			boolean resultadoVerificaçao = AssinaturaService.verificaArquivoAssinado(new FileInputStream (arquivoOriginal));
		} catch (FileNotFoundException e) {
			throw new FileNotFoundException("Arquivo inexistente: " + e.getMessage()); } */
		
		
		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(BRyApplication.class, args);
	}
}