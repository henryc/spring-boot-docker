package com.example.springbootdocker;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AppController {

	@GetMapping("/detail")
	public String detail(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
		Object uidObj = principal.getFirstAttribute("urn:oid:2.16.840.1.113730.3.1.241");		//Display Name
		model.addAttribute("name", String.valueOf(uidObj));
		return "detail";
	}
	
	@GetMapping("/user/logout")
	public String logout(Model model) {
		return "logout";
	}

}
