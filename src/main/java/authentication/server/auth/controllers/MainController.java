package authentication.server.auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
	
	@GetMapping("/home")
	public String home() {
		return "home";
	}
	@GetMapping("/nohome")
	public String nohome() {
		return "nohome";
	}
	
}
