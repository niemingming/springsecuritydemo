### 1.环境
springboot 2.1.4<br/>
security 2.1.4<br/>
jwt 0.10.5<br/>

### 2.基础说明
springsecurity是基于aop思想的，里面有大量的拦截器；其中定义拦截器顺序的核心类为:<br>
#### 1.FilterComparator<br>
该类，不仅仅是定义了拦截器的顺序，同时负责注册过滤器、移除过滤器等操作。
```
FilterComparator() {
		Step order = new Step(INITIAL_ORDER, ORDER_STEP);
		put(ChannelProcessingFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		put(WebAsyncManagerIntegrationFilter.class, order.next());
		put(SecurityContextPersistenceFilter.class, order.next());
		put(HeaderWriterFilter.class, order.next());
		put(CorsFilter.class, order.next());
		put(CsrfFilter.class, order.next());
		put(LogoutFilter.class, order.next());
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				order.next());
		put(X509AuthenticationFilter.class, order.next());
		put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
		filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter",
				order.next());
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				order.next());
		put(UsernamePasswordAuthenticationFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		filterToOrder.put(
				"org.springframework.security.openid.OpenIDAuthenticationFilter", order.next());
		put(DefaultLoginPageGeneratingFilter.class, order.next());
		put(DefaultLogoutPageGeneratingFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		put(DigestAuthenticationFilter.class, order.next());
		filterToOrder.put(
				"org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter", order.next());
		put(BasicAuthenticationFilter.class, order.next());
		put(RequestCacheAwareFilter.class, order.next());
		put(SecurityContextHolderAwareRequestFilter.class, order.next());
		put(JaasApiIntegrationFilter.class, order.next());
		put(RememberMeAuthenticationFilter.class, order.next());
		put(AnonymousAuthenticationFilter.class, order.next());
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				order.next());
		put(SessionManagementFilter.class, order.next());
		put(ExceptionTranslationFilter.class, order.next());
		put(FilterSecurityInterceptor.class, order.next());
		put(SwitchUserFilter.class, order.next());
	}
```
#### 2.UsernamePasswordAuthenticationFilter
该过滤器主要用于登录认证，从源码中可以看出来，针对/login和post请求做处理。我们如果要自己定义一些登录逻辑可以重写该类。<br>
一般来说，该类的默认实现就够了，因为security提供了其他途径去影响登录过程，但是我们这里需要在登录成功之后将jwttoken写入。我们有以下两种途径
1. 实现AuthenticationSuccessHandler，然后在filter中设置
2. 继承UsernamePasswordAuthenticationFilter然后重写successfulAuthentication方法
我们这里采用第二种：
```
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        UserDetails details = (UserDetails) authResult.getPrincipal();
        System.out.println("登录成功：" + details.getUsername());

        StringJoiner joiner = new StringJoiner(",","","");
        details.getAuthorities().forEach(a -> joiner.add(a.getAuthority()));

        String token = jwtUtil.createToken("username",details.getUsername(),"role",joiner.toString());
        response.setHeader("Authorization",token);

    }
```
#### 3.UserDetailsService
该接口是为我们预留的，自定义用户信息获取接口，我们可以实现该接口来自定义登录信息获取方式，一般配套的还要UserDetails和GrantedAuthory接口。
```
@Component
public class JwtUserService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("加载人员信息数据，包括角色信息！");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //我们暂时不实现UserDetails，使用默认的User，后面考虑查询数据库
        if (authentication != null) {
            return new User(authentication.getName(),null,authentication.getAuthorities());
        }else {
            return new User(username,passwordEncoder.encode("123456"), Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
        }
    }
}
```
#### 4.BasicAuthenticationFilter
这个过滤器，不是特定功能的，我们这里需要实现一个过滤器，用于解析请求中的jwttoken，完成授权信息。
```
public class JwtInfoFilter extends BasicAuthenticationFilter {

    private JwtUtil jwtUtil;

    public JwtInfoFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String auth = request.getHeader("Authorization");
        if (auth == null) {
            chain.doFilter(request,response);
            return;
        }
        String username = jwtUtil.parseToken(auth).get("username")+"";
        String role = jwtUtil.parseToken(auth).get("role")+"";
        //读取权限
        List<GrantedAuthority> grantedAuthorities = Arrays.asList(role.split(",")).stream()
                .map(r -> {
                    return new SimpleGrantedAuthority(r);
                }).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        chain.doFilter(request,response);
    }
}

```
#### 5.PasswordEncoder
这个是security用于密码编码接口，我们使用自带的BCryptPasswordEncoder即可。
### 3.小结
到这一步我们基本上完成了登录和访问权限验证的过程。如果我们没有额外的鉴权需求的话。下面是配置文件信息：
```
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtUserService jwtUserService;
    @Autowired
    private JwtUtil jwtUtil;
    /**
     * 配置鉴权信息
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserService)
                .passwordEncoder(passwordEncoder());//指定密码处理器
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    /**
     * 配置鉴权信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/book").hasAnyRole("admin".toUpperCase())
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
//                .sessionManagement().disable()
                .addFilterBefore(usernamePasswordAuthenticationFilter(), LogoutFilter.class)
                .addFilterBefore(jwtInfoFilter(),LogoutFilter.class);
    }

    @Bean
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        JwtUsernamePasswordFilter usernamePasswordFilter = new JwtUsernamePasswordFilter();
        usernamePasswordFilter.setAuthenticationManager(authenticationManagerBean());
        usernamePasswordFilter.setJwtUtil(jwtUtil);
        return usernamePasswordFilter;
    }
    @Bean
    public JwtInfoFilter jwtInfoFilter() throws Exception {
        JwtInfoFilter filter = new JwtInfoFilter(authenticationManagerBean());
        filter.setJwtUtil(jwtUtil);
        return filter;
    }
}
```
### 4.动态获取权限域认证
#### 6.FilterSecurityInterceptor
这个过滤器是用于鉴权认证的核心过滤器，从父类源码中我们可以看到：
其核心是<br>
* SecurityMetadataSource：用于加载权限要求的。
    * 我们只需要实现该接口并覆盖即可。
* AccessDecisionManager:用于进行权限验证的。
    * 进步分析该接口的三个实现类，发现我们只需要实现AccessDecisionVoter接口，使用自带的AffirmativeBased即可
```
protected InterceptorStatusToken beforeInvocation(Object object) {
		Assert.notNull(object, "Object was null");
		final boolean debug = logger.isDebugEnabled();

		if (!getSecureObjectClass().isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException(
					"Security invocation attempted for object "
							+ object.getClass().getName()
							+ " but AbstractSecurityInterceptor only configured to support secure objects of type: "
							+ getSecureObjectClass());
		}

		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource()
				.getAttributes(object);

		if (attributes == null || attributes.isEmpty()) {
			if (rejectPublicInvocations) {
				throw new IllegalArgumentException(
						"Secure object invocation "
								+ object
								+ " was denied as public invocations are not allowed via this interceptor. "
								+ "This indicates a configuration error because the "
								+ "rejectPublicInvocations property is set to 'true'");
			}

			if (debug) {
				logger.debug("Public object - authentication not attempted");
			}

			publishEvent(new PublicInvocationEvent(object));

			return null; // no further work post-invocation
		}

		if (debug) {
			logger.debug("Secure object: " + object + "; Attributes: " + attributes);
		}

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			credentialsNotFound(messages.getMessage(
					"AbstractSecurityInterceptor.authenticationNotFound",
					"An Authentication object was not found in the SecurityContext"),
					object, attributes);
		}

		Authentication authenticated = authenticateIfRequired();

		// Attempt authorization
		try {
			this.accessDecisionManager.decide(authenticated, object, attributes);
		}
		catch (AccessDeniedException accessDeniedException) {
			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated,
					accessDeniedException));

			throw accessDeniedException;
		}

		if (debug) {
			logger.debug("Authorization successful");
		}

		if (publishAuthorizationSuccess) {
			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
		}

		// Attempt to run as a different user
		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object,
				attributes);

		if (runAs == null) {
			if (debug) {
				logger.debug("RunAsManager did not change Authentication object");
			}

			// no further work post-invocation
			return new InterceptorStatusToken(SecurityContextHolder.getContext(), false,
					attributes, object);
		}
		else {
			if (debug) {
				logger.debug("Switching to RunAs Authentication: " + runAs);
			}

			SecurityContext origCtx = SecurityContextHolder.getContext();
			SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
			SecurityContextHolder.getContext().setAuthentication(runAs);

			// need to revert to token.Authenticated post-invocation
			return new InterceptorStatusToken(origCtx, true, attributes, object);
		}
	}
```
#### 7.FilterInvocationSecurityMetadataSource
用于权限配置信息获取
```
package com.nmm.study.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;

@Component
public class JwtInvocationMetadataSource extends DefaultFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private AntPathMatcher matcher = new AntPathMatcher();

    public JwtInvocationMetadataSource() {
        super(new LinkedHashMap<>());
    }

    /**
     * 根据请求获取权限要求filterInvocation
     * @param object
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation filterInvocation = (FilterInvocation) object;
        System.out.println("获取权限规则：" + filterInvocation.getRequestUrl());
        filterInvocation.getRequestUrl();
        for (ConfigAttribute configAttribute : getAllConfigAttributes()) {
            JwtConfigAttribute attribute = (JwtConfigAttribute) configAttribute;
            if (matcher.match(attribute.getPath(),filterInvocation.getRequestUrl())){
                return Arrays.asList(attribute);
            }
        }
        return null;
    }

    /**
     * 获取所有角色
     * @return
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        JwtConfigAttribute configAttribute = new JwtConfigAttribute();
        configAttribute.setPath("/api/book");
        configAttribute.setRoles(Arrays.asList("admin".toUpperCase()));
        return Arrays.asList(configAttribute);
    }

}

```
#### 8.AccessDecisionVoter
用于权限验证
```
@Component
public class JwtAutheticationVotor implements AccessDecisionVoter<FilterInvocation> {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof JwtConfigAttribute;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * 校验逻辑
     * @param authentication
     * @param object
     * @param attributes
     * @return
     */
    @Override
    public int vote(Authentication authentication, FilterInvocation object, Collection<ConfigAttribute> attributes) {
        if (attributes == null) {
            //无限制
            return ACCESS_GRANTED;
        }
        System.out.println("校验权限：");
        for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
            for (ConfigAttribute attribute : attributes) {
                if (attribute instanceof JwtConfigAttribute){
                    JwtConfigAttribute jwtConfigAttribute = (JwtConfigAttribute) attribute;
                    for (String s : jwtConfigAttribute.getRoles()) {
                        if (s.equalsIgnoreCase(grantedAuthority.getAuthority())){
                            return ACCESS_GRANTED;
                        }
                    }
                }
            }
        }
        return ACCESS_DENIED;
    }
}

```
接下来，我们需要把他们配置进去，最终的配置文件如下：
```
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtUserService jwtUserService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private JwtInvocationMetadataSource jwtInvocationMetadataSource;
    @Autowired
    private JwtAutheticationVotor jwtAutheticationVotor;
    /**
     * 配置鉴权信息
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserService)
                .passwordEncoder(passwordEncoder());//指定密码处理器
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    /**
     * 配置鉴权信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .accessDecisionManager(accessDecisionManager())//权限验证处理
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {//权限规则获取
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(jwtInvocationMetadataSource);
                        return object;
                    }
                })
                .antMatchers("/api/book").hasAnyRole("admin".toUpperCase())
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
//                .sessionManagement().disable()
                .addFilterBefore(usernamePasswordAuthenticationFilter(), LogoutFilter.class)
                .addFilterBefore(jwtInfoFilter(),LogoutFilter.class);
    }

    @Bean
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        JwtUsernamePasswordFilter usernamePasswordFilter = new JwtUsernamePasswordFilter();
        usernamePasswordFilter.setAuthenticationManager(authenticationManagerBean());
        usernamePasswordFilter.setJwtUtil(jwtUtil);
        return usernamePasswordFilter;
    }
    @Bean
    public JwtInfoFilter jwtInfoFilter() throws Exception {
        JwtInfoFilter filter = new JwtInfoFilter(authenticationManagerBean());
        filter.setJwtUtil(jwtUtil);
        return filter;
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDecisionManager accessDecisionManager(){

        List<AccessDecisionVoter<? extends Object>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new JwtAutheticationVotor());

        AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
        return accessDecisionManager;
    }
}

```