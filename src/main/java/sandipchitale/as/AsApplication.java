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
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;

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

	public final class JwtRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
		private final JwtEncoder jwtEncoder;
		private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

		public JwtRefreshTokenGenerator(JwtEncoder jwtEncoder) {
			Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
			this.jwtEncoder = jwtEncoder;
		}

		@Override
		public OAuth2RefreshToken generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null ||
					!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
				return null;
			}

			RegisteredClient registeredClient = context.getRegisteredClient();

			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());

			// @formatter:off
			JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
			claimsBuilder
					.subject(context.getPrincipal().getName())
					.audience(Collections.singletonList(registeredClient.getClientId()))
					.issuedAt(issuedAt)
					.expiresAt(expiresAt)
			;
			// @formatter:on

			JwsHeader.Builder headersBuilder = JwsHeader.with(SignatureAlgorithm.RS256);

			if (this.jwtCustomizer != null) {
				// @formatter:off
				JwtEncodingContext.Builder jwtContextBuilder = JwtEncodingContext.with(headersBuilder, claimsBuilder)
						.registeredClient(context.getRegisteredClient())
						.principal(context.getPrincipal())
						.authorizedScopes(context.getAuthorizedScopes())
						.tokenType(context.getTokenType())
						.authorizationGrantType(context.getAuthorizationGrantType());
				if (context.getAuthorization() != null) {
					jwtContextBuilder.authorization(context.getAuthorization());
				}
				if (context.getAuthorizationGrant() != null) {
					jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant());
				}
				// @formatter:on

				JwtEncodingContext jwtContext = jwtContextBuilder.build();
				this.jwtCustomizer.customize(jwtContext);
			}

			JwsHeader headers = headersBuilder.build();
			JwtClaimsSet claims = claimsBuilder.build();

			Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(headers, claims));

			return new OAuth2RefreshToken(jwt.getTokenValue(), issuedAt, expiresAt);
		}

		public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
			Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
			this.jwtCustomizer = jwtCustomizer;
		}

	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(@Qualifier("sharedSecretJwtEncoder") JwtEncoder jwtEncoder,
												  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtCustomizer);

		JwtRefreshTokenGenerator jwtRefreshTokenGenerator = new JwtRefreshTokenGenerator(jwtEncoder);
		jwtRefreshTokenGenerator.setJwtCustomizer(jwtCustomizer);

		return new DelegatingOAuth2TokenGenerator(jwtGenerator,
				jwtRefreshTokenGenerator);
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
			context.getClaims().claim("token_type", context.getTokenType().getValue());
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
