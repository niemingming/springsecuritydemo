<h2>1.springsecurity配置</h2>
1. 说明
    security与springcloudgateway的集成。由于springcloudgateway在2.x之后使用了webflux框架，也就是响应式编程模式；
    传统的security对此并不支持，传统security是基于aop思想的，这里是基于事件响应的。为此security提供了支持，使用@EnableWebFluxSecurity配置即可。
    
2. 学习方法

    参看EnableWebFluxSecurity源码，在其上引入的ServerHttpSecurityConfiguration.class, WebFluxSecurityConfiguration.class,
    ReactiveOAuth2ClientImportSelector.class配置信息，通过这些我们参看具体的配置。通过查询我们知道一下几点
    1. 发现我们很多东西比如ReactiveUserDetailsService 之类的，我们只需要加入到spring容器中即可完成覆盖。
    2. SecurityWebFiltersOrder 定义了核心过滤器的优先级，从源码看，权限校验的优先级是最高的，从最小整数递增的。
    3. ServerHttpSecurity 是配置权限信息的核心配置类。
    4. AuthenticationWebFilter 默认的登录过滤器，我们不做特殊处理，只需要实现ReactiveUserDetailsService实现
    5. AuthorizationWebFilter 鉴权过滤器，这个过滤器目前比较封闭，如果要定义自己逻辑，需要自己实现一个ReactiveAuthorizationManager，并添加新的过滤器
    6. ReactorContextWebFilter 权限过滤器，负责权限信息提取
    
<h2>2.集成jwt与gateway与security</h2>
* 1.pom文件

```
<parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.4.RELEASE</version>
    </parent>

    <dependencies>
        <!--引入gateway，gateway采用webflux，不需要引入springbootweb-->
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-gateway</artifactId>
            <version>2.1.1.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!--由于引入gateway缺少了对于j2ee的依赖-->
        <dependency>
            <groupId>javax</groupId>
            <artifactId>javaee-api</artifactId>
            <version>7.0</version>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.0</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.10.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.10.5</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.10.5</version>
            <scope>runtime</scope>
        </dependency>

        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.54</version>
        </dependency>
    </dependencies>
```
* 2.实现ReactiveUserDetailsService

我们想要自己获取用户信息不采用默认配置方式，可以自己实现ReactiveUserDetailsService接口并纳入到spring管理即可
这里我们只是写个示例，后续可以改为数据库获取方式，注意这里的PasswordEncoder我们使用的是BCrytPasswordEncoder，这里面有响应式编程的语法

```
@Component
public class JwtReactiveUserDetailsService implements ReactiveUserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 模拟操作
     * @param username
     * @return
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        System.out.println("获取用户信息：" + username);
        //指定密码编译器
        return Mono.just(User.withUsername(username).passwordEncoder(passwordEncoder::encode)
                              .password("123456")
                                .authorities("admin".toUpperCase())
                                .build());
    }
}
```
* 3.实现LoginSuccessHandler接口
    
    默认的登录过滤器，基本能够满足需求，不同的是我们需要重写在登录成功之后的逻辑，要将jwttoken放到请求中返回给前台。因此
    
    我们实现LoginSuccessHandleer接口，进行配置
    
```
@Component
public class JwtLoginSuccessHandler implements ServerAuthenticationSuccessHandler {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {

        UserDetails details = (UserDetails) authentication.getPrincipal();
        System.out.println("登录成功：" + details.getUsername());

        StringJoiner joiner = new StringJoiner(",","","");
        details.getAuthorities().forEach(a -> joiner.add(a.getAuthority()));

        String token = jwtUtil.createToken("username",details.getUsername(),"role",joiner.toString());
//        webFilterExchange..setHeader("Authorization",token);
        webFilterExchange.getExchange().getResponse().getHeaders().add("Authorization",token);
        return webFilterExchange.getExchange().getResponse().setComplete();
    }
}
```    
* 4.实现ServerSecurityContextRepository

    改接口是ReactorContextWebFilter进行权限过滤时获取用户权限信息的实现，我们实现它从token中获取用户权限。
    
```
@Component
public class JwtServerSecurityContextRepository implements ServerSecurityContextRepository {
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * 不保存
     * @param exchange
     * @param context
     * @return
     */
    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }

    /**
     * 加载信息,这里同时承载了用户信息
     * @param exchange
     * @return
     */
    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        System.out.println("进来了，校验登录信息！");
        SecurityContext context = null;

        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (auth == null) {
            return Mono.empty();
        }
        String username = jwtUtil.parseToken(auth).get("username")+"";
        String role = jwtUtil.parseToken(auth).get("role")+"";
        //读取权限
        List<GrantedAuthority> grantedAuthorities = Arrays.asList(role.split(",")).stream()
                .map(r -> {
                    return new SimpleGrantedAuthority(r);
                }).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
        context = new SecurityContextImpl(token);
        return Mono.justOrEmpty(context);
    }
}
```
到这一步，我们基本的权限登录、鉴权就做完了，但是如果你不想使用spring默认的鉴权操作，我们需要使用自己的逻辑该怎么做呢？

* 5.实现ReactiveAuthorizationManager

    其实AuthorizationWebFilter本身的鉴权流程和逻辑，不用动，我们只需要为其指定自己逻辑的ReactiveAuthorizationManager即可实现鉴权。
    
```
@Component
public class JwtReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerWebExchange>,InitializingBean{

    private Map<String,List<String>> grantes = new HashMap<>();
    private AntPathMatcher matcher = new AntPathMatcher();

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, ServerWebExchange exchange) {
        System.out.println("check granted::" + exchange.getRequest().getURI().getPath());

        return Flux.fromIterable(grantes.entrySet())
                .filter(grant -> matcher.match(grant.getKey(),exchange.getRequest().getURI().getPath()))
                .flatMap(g -> authentication.flatMap(au ->{
                    long count = au.getAuthorities().stream().filter( grantedAuthority -> {
                        return g.getValue().contains(grantedAuthority.getAuthority().toLowerCase());
                    }).count();
                    return Mono.just(new AuthorizationDecision(count > 0));
                })).next().defaultIfEmpty(new AuthorizationDecision(false));

    }

    @Override
    public void afterPropertiesSet() throws Exception {
        grantes.clear();
        grantes.put("/api/book", Arrays.asList("admin","employee"));

    }

}

```

* 6.配置SecurityConfiguration

```

/**
 * 基于webflux模式的security配置
 * 代码餐卡EnableWebFluxSecurity的注释
 *
 * AuthenticationWebFilter:登录
 * AuthorizationWebFilter: 鉴权
 * ReactorContextWebFilter:过滤获取权限信息通过ServerSecurityContextRepository获取权限信息
 *
 * 从注解进入相关引入的配置，我们可以看到webflux的配置，更多的使用了spring的特性。
 * 我们注入了bean，就会使用。
 *
 * 关键过滤器是webfilter
 *
 */
@EnableWebFluxSecurity
public class JwtWebFluxSecurityConfiguration {
    @Autowired
    private JwtLoginSuccessHandler jwtLoginSuccessHandler;
    @Autowired
    private JwtServerSecurityContextRepository jwtServerSecurityContextRepository;
    @Autowired
    private JwtReactiveAuthorizationManager jwtReactiveAuthorizationManager;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity){

        httpSecurity.authorizeExchange()
                .anyExchange().authenticated()
                .and()
                .addFilterAt(new AuthorizationWebFilter(jwtReactiveAuthorizationManager), SecurityWebFiltersOrder.AUTHORIZATION)
                .csrf().disable()//暂时禁用，不考虑csrf攻击我们不适用session
                .securityContextRepository(jwtServerSecurityContextRepository)
                .formLogin()
                .authenticationSuccessHandler(jwtLoginSuccessHandler);
        //从源码看，其formlogin是写死的参数获取方式，我们如果要覆盖不通过form表单获取登录信息。

        return httpSecurity.build();
    }
}
```
