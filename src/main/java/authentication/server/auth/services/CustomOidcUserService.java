package authentication.server.auth.services;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import authentication.server.auth.entity.Employee;
import authentication.server.auth.entity.Role;


@Service
public class CustomOidcUserService  extends OidcUserService {

	@Autowired
	private EmployeeService employeeService;

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) {

	    OidcUser oidcUser = super.loadUser(userRequest);

	    String email = oidcUser.getAttribute("email");
	    String name = oidcUser.getAttribute("given_name");
	    String surname = (oidcUser.getAttribute("family_name") != null) ? oidcUser.getAttribute("family_name") : "default_surname";

	    Employee employee = employeeService.findByEmployeeEmail(email);
	    Collection<GrantedAuthority> authorities = new ArrayList<>();

	    if (employee == null) {
	        employee = new Employee();
	        employee.setEmployeeName(name);
	        employee.setEmployeeSurName(surname);
	        employee.setEmployeeEmail(email);
	        employee.setRole(Role.DEFAULT);
	        employeeService.saveEmployee(employee);
	    }

	    SimpleGrantedAuthority empRole = new SimpleGrantedAuthority("ROLE_" + employee.getRole().toString());
	    authorities.add(empRole);

	    return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
	}
}