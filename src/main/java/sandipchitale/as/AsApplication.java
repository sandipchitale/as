package sandipchitale.as;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
public class AsApplication {
	public static void main(String[] args) {
		SpringApplication.run(AsApplication.class, args);
	}

	@RestController
	public static class IndexController {

		@GetMapping("/")
		public String index() {
			return "Authorization Server";
		}
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity,
																	  OAuth2TokenGenerator<?> tokenGenerator,
																	  RegisteredClientRepository registeredClientRepository) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer =
				httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		oAuth2AuthorizationServerConfigurer.registeredClientRepository(registeredClientRepository);
		oAuth2AuthorizationServerConfigurer.tokenGenerator(tokenGenerator);

		httpSecurity
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling((exceptions) -> exceptions
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
						)
				);
		return httpSecurity.build();
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(@Qualifier("sharedSecretJwtEncoder") JwtEncoder jwtEncoder,
												  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtCustomizer);
		return jwtGenerator;
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			JwsHeader.Builder headers = context.getJwsHeader();
			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) ||
					context.getTokenType().equals(OAuth2TokenType.REFRESH_TOKEN)) {
				// We are using HS256 with shared secret key
				headers.algorithm(MacAlgorithm.HS256);
			}
		};
	}

	@Bean
	@Qualifier("sharedSecretJwtEncoder")
	public JwtEncoder jwtEncoder(@Qualifier("sharedSecretJwkSource") JWKSource<SecurityContext> jwkSource) {
		// Use shared secret
		return new NimbusJwtEncoder(jwkSource);
	}

	// Shared secret key base JWKSource
	@Bean
	@Qualifier("sharedSecretJwkSource")
	public JWKSource<SecurityContext> jwkSource(@Value("${jwt.shared-secret-key}") String sharedSecretKey) {
		return new ImmutableSecret<SecurityContext>(
				new SecretKeySpec(sharedSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
	}


	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 100)
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
					authorizationManagerRequestMatcherRegistry
							.anyRequest().fullyAuthenticated();
				})
				.formLogin(withDefaults());
		return httpSecurity.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
		UserDetails userDetails = User
				.withUsername("user")
				.password("password")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

}
