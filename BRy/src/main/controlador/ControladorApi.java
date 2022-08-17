package main.controlador;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("testeBRy")
public class ControladorApi {
	
	@RequestMapping(value = "/signature", method = RequestMethod.POST)
	public String signature(@RequestParam("pfx") MultipartFile pfx,@RequestParam("arquivo") MultipartFile arquivo, @RequestParam("alias") String alias, @RequestParam("senha") String senha, HttpServletRequest request) {
		
		String resultado = null;
		
		try {
		InputStream pfxStream;
		pfxStream = pfx.getInputStream(); //juntar

		//converte de multipartfile para inputstream //estudar
		InputStream arquivoOriginal = arquivo.getInputStream();
		
		//tem que usar base64 to file
		//assina e retorna assinatura digital Em Formato Base 64 como resposta da req
		resultado = AssinaturaService.assinador(arquivoOriginal, pfxStream, alias, senha);
		
		} catch (IOException e) {
			return "Erro na leitura do arquivo.";
		}
		return resultado;
	}
	
	
	@RequestMapping(value = "/verify", method = RequestMethod.POST)
	public String verify(@RequestParam("arquivo") MultipartFile arquivo, @RequestParam("assinatura") MultipartFile assinatura, HttpServletRequest request) {
		boolean sucesso = false;
		try {
			//chama o método de verificação, trata os erros e retorna o status
			sucesso = AssinaturaService.verificaArquivoAssinado(arquivo.getInputStream(), assinatura.getInputStream());
		} catch (IOException e) {
			return "Erro na Leitura/Escrita.";
		} catch (Exception e) {
			return "Erro na verificação da assinatura.";
		}
		if(sucesso) {
			return "STATUS: Assinatura válida";
		}
		return "STATUS: Assinatura inválida.";
	}
}