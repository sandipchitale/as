package sandipchitale.as;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.core.ApplicationFilterChain;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * This registers a filter to dump all the configured filter and security filter chains.
 *
 * Used for debugging security filter chains configured using HttpSecurity.
 *
 * @author schitale
 * @since 23.4
 */
@Configuration
public class DumpFiltersConfig {
    public static class DumpFilters extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, IOException {
            if (filterChain instanceof ApplicationFilterChain) {
                try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                     PrintStream out = new PrintStream(byteArrayOutputStream);) {
                    out.println();
                    out.println("Begin Filters ============================");
                    out.println("URL: " + request.getMethod() + " " + request.getRequestURI());
                    ApplicationFilterChain applicationFilterChain = (ApplicationFilterChain) filterChain;
                    try {
                        Field filters = applicationFilterChain.getClass().getDeclaredField("filters");
                        filters.setAccessible(true);
                        ApplicationFilterConfig[] filterConfigs = (ApplicationFilterConfig[]) filters
                                .get(applicationFilterChain);
                        boolean firstMatched = false;
                        for (ApplicationFilterConfig applicationFilterConfig : filterConfigs) {
                            if (applicationFilterConfig != null) {
                                out.println("Filter Name: " + applicationFilterConfig.getFilterName()
                                        + " FilterClass: " + applicationFilterConfig.getFilterClass());
                                if (applicationFilterConfig.getFilterName().equals("springSecurityFilterChain")) {
                                    try {
                                        Method getFilter = applicationFilterConfig.getClass()
                                                .getDeclaredMethod("getFilter");
                                        getFilter.setAccessible(true);
                                        DelegatingFilterProxy delegatingFilterProxy = (DelegatingFilterProxy) getFilter
                                                .invoke(applicationFilterConfig);
                                        Field delegateField = DelegatingFilterProxy.class.getDeclaredField("delegate");
                                        delegateField.setAccessible(true);
                                        FilterChainProxy filterChainProxy = null;
                                        if (delegateField.get(delegatingFilterProxy) instanceof FilterChainProxy) {
                                            filterChainProxy = (FilterChainProxy) delegateField.get(delegatingFilterProxy);
                                        }
                                        if (delegateField.get(delegatingFilterProxy) instanceof DebugFilter debugFilter) {
                                            // DebugFilter debugFilter = (DebugFilter) delegateField.get(delegatingFilterProxy);
                                            out.println("\torg.springframework.security.web.debug.DebugFilter");
                                            filterChainProxy = debugFilter.getFilterChainProxy();
                                        }
                                        if (filterChainProxy != null) {
                                            List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
                                            out.println("Begin Filter Chains ============================");
                                            for (SecurityFilterChain securityFilterChain : filterChains) {
                                                DefaultSecurityFilterChain defaultSecurityFilterChain = (DefaultSecurityFilterChain) securityFilterChain;
                                                RequestMatcher requestMatcher = defaultSecurityFilterChain.getRequestMatcher();
                                                printRequestMatcher(requestMatcher, "\t", out);
                                                if (!firstMatched && defaultSecurityFilterChain.getRequestMatcher().matches(request)) {
                                                    firstMatched = true;
                                                    out.println("\t\t✅ " + request.getMethod() + " " + request.getRequestURI() + " Matched ✅");
                                                }
                                                List<Filter> securityFilters = securityFilterChain.getFilters();
                                                for (Filter securityFilter : securityFilters) {
                                                    out.println("\t\t" + securityFilter);
                                                }
                                            }
                                            out.println("End Filter Chains ==============================");
                                        }
                                    } catch (NoSuchMethodException | InvocationTargetException e) {
                                        out.println(e.getMessage());
                                    }
                                }
                            }
                        }
                    } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                        System.err.println(e.getMessage());
                    }
                    out.println("End Filters ==============================");
                    System.out.print(byteArrayOutputStream.toString(StandardCharsets.UTF_8));
                }
            }
            filterChain.doFilter(request, response);
        }
    }

    // Recursive method to print RequestMatcher and its sub RequestMatchers
    private static void printRequestMatcher(RequestMatcher requestMatcher, String indent, PrintStream out) {
        if (requestMatcher instanceof OrRequestMatcher orRequestMatcher) {
            out.println(indent + "Or");
            // OrRequestMatcher orRequestMatcher = (OrRequestMatcher) requestMatcher;
            Field requestMatchersField = ReflectionUtils.findField(OrRequestMatcher.class, "requestMatchers");
            ReflectionUtils.makeAccessible(requestMatchersField);
            List<RequestMatcher> requestMatchers =
                    (List<RequestMatcher>) ReflectionUtils.getField(requestMatchersField, requestMatcher);
            requestMatchers.forEach((RequestMatcher rm) -> {
                printRequestMatcher(rm, indent + "\t", out);
            });
        } else if (requestMatcher instanceof AndRequestMatcher andRequestMatcher) {
            out.println(indent + "And");
            // AndRequestMatcher andRequestMatcher = (AndRequestMatcher) requestMatcher;
            Field requestMatchersField = ReflectionUtils.findField(AndRequestMatcher.class, "requestMatchers");
            ReflectionUtils.makeAccessible(requestMatchersField);
            List<RequestMatcher> requestMatchers =
                    (List<RequestMatcher>) ReflectionUtils.getField(requestMatchersField, requestMatcher);
            requestMatchers.forEach((RequestMatcher rm) -> {
                printRequestMatcher(rm, indent + "\t", out);
            });
        } else if (requestMatcher instanceof NegatedRequestMatcher negatedRequestMatcher) {
            out.println(indent + "Not");
            // NegatedRequestMatcher negatedRequestMatcher = (NegatedRequestMatcher) requestMatcher;
            Field requestMatcherField = ReflectionUtils.findField(NegatedRequestMatcher.class, "requestMatcher");
            ReflectionUtils.makeAccessible(requestMatcherField);
            RequestMatcher rm = (RequestMatcher) ReflectionUtils.getField(requestMatcherField, requestMatcher);
            printRequestMatcher(rm, indent + "\t", out);
        } else {
            out.println(indent + requestMatcher);
            // Check if lambda - get the arg$1
            Field requestMatcherField = ReflectionUtils.findField(requestMatcher.getClass(), "arg$1");
            if (requestMatcherField != null) {
                ReflectionUtils.makeAccessible(requestMatcherField);
                Object o = ReflectionUtils.getField(requestMatcherField, requestMatcher);
                if (o != null) {
                    // Special case of OAuth2AuthorizationServerConfigurer.endpointsMatcher
                    Field endpointsMatcherField = ReflectionUtils.findField(o.getClass(), "endpointsMatcher");
                    if (endpointsMatcherField != null) {
                        ReflectionUtils.makeAccessible(endpointsMatcherField);
                        RequestMatcher rm = (RequestMatcher) ReflectionUtils.getField(endpointsMatcherField, o);
                        printRequestMatcher(rm, indent + "\t", out);
                    }
                }
            }
        }
    }

    @Bean
    FilterRegistrationBean<DumpFilters> filters() {
        FilterRegistrationBean<DumpFilters> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new DumpFilters());
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registrationBean;
    }
}