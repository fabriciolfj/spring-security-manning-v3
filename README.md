# Spring security (spring framework 6)

# ATUALIZACAO
```
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.headers(c -> c.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.httpBasic(Customizer.withDefaults());
        http.authorizeHttpRequests(c -> c.requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/h2-console/**")).permitAll()
                .requestMatchers(AntPathRequestMatcher.antMatcher("/js/**")).permitAll()
                .requestMatchers(AntPathRequestMatcher.antMatcher("/css/**")).permitAll()
                .requestMatchers(AntPathRequestMatcher.antMatcher("/images/**")).permitAll()
                .anyRequest().authenticated());

        return http.build();
    }
```
- quando cria-se um projeto spring, o mesmo vem com algumas configurações padrões, dependendo das dependências inseridas
- no caso do spring security, ja temos o metodo Basic configurado como padrão de autenticação e os seguintes componentes criados:

#### Authentication filter
- delega a autenticação para o authentication manager
- com base na resposta do authentication manager, configura o contexto de segurança

#### Authentication manager
- utiliza um provedor de autenticação para processar a autenticação

#### Authentication provider
- possui a lógica de autenticação
- costuma-se utilizar o UserDetailsService e o password encoder
  - ele recebe a solicitação do authentication manager
  - delega a localização para o user details service
  - e a verificação da senha para o password encoder

#### UserDetailsService
- implementa a responsabilidade de gerenciamento do usuário (utilize a classe User do spring framework para criar um usuário -> implementação de UserDetails)
- como recuperar o usuário
- abaixo uma exemplo de implementação do UserDetailService
```
return new InMemoryUserDetailsManager(user);
```

#### UserDetailsManager
- responsável por modificar, adicionar ou excluir um usuário.

#### UserDetails
- implementa como descrever um usuário da maneira que o framework entende
- ou seja, ele descreve o usuário
- para o spring security, uma definição de usuário deve respeitar o contrato UserDetails (a classe precisa implementar UserDetails)

#### GrantedAuthority
- autoridades que o usuário possui

#### Password encoder
- implementa o gerenciamento de senha
- codifica uma senha
- verifica se a senha corresponde a uma codificação existente

#### Security context
- mantem os dados de autenticação apõs o processo de autenticação.

## Personalizando a configuração
- para personalizar a configuração padrão do spring security, precisamos substituir os pontos salientados acima;
- no exemplo abaixo estamos fornecendo um user details service e um novo password encoder (user details depende dele, se não fornecedor quando o personalizamos, não funcionará):
```
    @Bean
    UserDetailsService userDetailsService() {
        var user = User.withUsername("fabricio")
                .password("1234")
                .authorities("read")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
```

## UserDetailsService
- cuida do gerenciamento dos usuários
- uma forma de recuperar o usuário de algum local, seja em uma base de dados ou memória
- possui apenas um método loadUserByname, que recebi o nome do usuário
- a forma de buscar, a implementação da interface UserDetailsService executa
- o retorno é uma implementação do UserDetails

## GrantedAuthority
- definie uma função dentro do aplicativo que é permitida ao usuário


### JdbcUserDetailsManager
- é uma implementação do UserDetailsService
- possui um script default que receber o usuário e suas autoridades na base de dados
- independente do sistema DBMS
- caso seja utilizado, é chamado no authentication provider
- caso utilize um schema diferente do padrão jdbcuserdetailsmanager, podemos personalizar, conforme demonstrado abaixo:
```
@Bean
public UserDetailsService userDetailsService(DataSource dataSource) {
  String usersByUsernameQuery = 
     "select username, password, enabled
      [CA]from users where username = ?";
  String authsByUserQuery =
     "select username, authority
      [CA]from spring.authorities where username = ?";
 
  var userDetailsManager = new JdbcUserDetailsManager(dataSource);
  userDetailsManager.setUsersByUsernameQuery(usersByUsernameQuery);
  userDetailsManager.setAuthoritiesByUsernameQuery(authsByUserQuery);
  return userDetailsManager;
}
```

## PasswordEncoder
- é uma interface
- o authorizationprovider utiliza-o para validar o password do usuário informado na requisição com o recuperado pela implementação do UserDetailsService
- serve para encriptar a senha
- e verificar o texto informado, corresponde ao texto codificado
```
public interface PasswordEncoder {
 
  String encode(CharSequence rawPassword);
  boolean matches(CharSequence rawPassword, String encodedPassword);
 
  default boolean upgradeEncoding(String encodedPassword) { 
    return false; 
  }
}
```

## DelegationPasswordEncoder
- quando temos um aplicativo que sua encriptação de senha será atualizada para os novos usuários
- mas não queremos mudar para os usuários antigos
- usamos o delegation, onde informamos qual encriptação utilizar, com base na chave informada (no exemplo abaixo o bcrypt e o default)
```
    @Bean
    public PasswordEncoder passwordEncoder() {
        final Map<String, PasswordEncoder> encoders = new HashMap<>();
        
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder(16000, 8 , 1, 32, 64));
        
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }
```

## Alguns conceitos
### Codificação
- e o processo de transformar uma entrada em uma saída diferente

### Criptografia
- é um tipo específico de codificação, aonde fornecemos uma chave (ou 2) junto com a entrada para trasformar-la e também valida-la posteriormente

#### Chave simétrica
- quando a chave que encripta e decripta o dado, são as mesmas

#### Chave assimétrica
- quando a chave que encripta (chave pública) e diferente da que decripta (chave privada)

### Hashing
- é um tipo de codificação, aonde não tem uma chave de entrada
- transformando a entrada de forma aleatória

## Geradores de chave
- utilizados para gerar um tipo de chave, que está é utilizada por algum algoritmo de criptografia ou hash.

## criptografadores
- criptografador implementa um algoritmo de criptografia.

# Filtros
- filtros interceptam uma requisição aplicando nela alguma lógica para seguir ou interromper.
- o spring secutiry fornece algumas implementações de filtros
- para implementar um filtro devemos implementar a interface Filter, aonde teremos:
  - servletRequest = para pegar a requisição
  - servletResponse = representa a resposta ao cliente, onde podemos modificar ela no filter ou delegar para outras etapas
  - filterChain = que representa a cadeia de filtros, com uma ordem definida (podemos inserir um filtro no meio dos filtros criados pelo spring, ou definir a ordem dele tambem)
- alguns filtros ja criados pelo spring security:
  - BasicAuthenticationFilter: cuida da autenticação http básica
  - csrfFilter: cuida da proteção contra falsificação de solicitação entre sites
  - corsFilter: cuida de regras de compartilhamento de recursos entre origens.
- quando temos filtros na mesma posição de chamada (na cadeia de filtros), a ordem não é definida.

### Exemplo colocando um filtro custom, antes de um existente
```
    @Bean
    SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        http.httpBasic();
        //http.authenticationProvider(authenticationProvider);

        http
                .addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests()
                .anyRequest()
                //.permitAll();
                .authenticated();

        return http.build();
    }
```
### Exemplo colocando um filtro custom, depois de um existente
```
.addFilterAfter(new AuthenticationLoggingFilter(), BasicAuthenticationFilter.class)
```

### Exemplo colocando um filtro na mesma posição de um existente
- nesse exemplo, o spring não substitui um pelo outro, teremos 2 filtros e a ordem deles é arbitrária
```
.addFilterAfter(new AuthenticationLoggingFilter(), BasicAuthenticationFilter.class)
```

### Algumas observações sobre filtros
- devemos ter cuidado em não abusar de filtros, podem deixar o sistema mais lento e confuso
- optar por algum mais simples como filter, embora spring oferece seus filtros como OncePerRequestFilter(executado apenas uma vez por solicitação) ou GenericFilterBean
- Ele suporta apenas solicitações HTTP, mas na verdade é o que sempre usamos. A vantagem é que ele lança os tipos e recebemos diretamente as solicitações como HttpServletRequeste HttpServletResponse. Lembre-se, com a Filterinterface, tivemos que lançar a solicitação e a resposta. 
- Você pode implementar a lógica para decidir se o filtro é aplicado ou não. Mesmo se você adicionar o filtro à cadeia, poderá decidir que ele não se aplica a determinadas solicitações. Você define isso substituindo o shouldNotFilter(HttpServletRequest)método. Por padrão, o filtro se aplica a todas as solicitações. 
- Por padrão, a não se aplica a solicitações assíncronas ou solicitações de despacho de erro. Você pode alterar esse comportamento substituindo os métodos e .OncePerRequestFilter shouldNotFilterAsyncDispatch()shouldNotFilterErrorDispatch()

# AuthenticationProvider
- e a camada responsável pela lógica de autenticação.
  - por padrão ele delega a busca do usuario ao UserDetailsService e PasswordEncoder para senha 
- nele encontra-se as condições e instruções que decidem pela autenticação ou não da solicitação.
- quem delega responsabilidade para ele é  authenticatinManager, que é chamado após a execução dos filtros
- quando fornecemos uma implementação do authenticationProvider, o spring prioriza ela em vez da default

## Processo de autenticação do authenticationProvider
- envolve a interface Authentication que extende a interface Principal
- interface AuthenticationProvider 
  - que possui o metodo isAuthenticated(), que podemos implementar nossa lógica para retornar true ou false
  - supports, que diz se aquele AuthenticationProvider, suporta tal classe que possui a lógica.

# SecurityContext
- o authenticationManager após concluir o processo de autenticação, ele armazena uma instancia autentication em um security context
- o spring oferece 3 maneiras de gerenciar  o securityContext como um objeto (security context holder):
  - MODE_THREADLOCAL -> permite que cada thread armazene seus próprios detalhes (comum/default)
  - MODE_INHERITABLETHREADLOCAL ->copia o contexto para a próxima thread, caso  método seja assincrono
  - MODE_GLOBAL -> faz com que todos os threads da app vejam a mesma instância do contexto de segurança

## propagar contexto de segurança para threads criadas fora do contexto spring
- para propagar o contexto de segurança a threads criadas fora do contexto spring (fora do @Async)
- podemos utilizar a classe DelegatingSecurityContextExecutor, conforme demonstrado abaixo:
```
    @GetMapping("/hola")
    public String hola() throws Exception {
        Callable<String> task = () -> {
            SecurityContext context = SecurityContextHolder.getContext();
            return context.getAuthentication().getName();
        };

        var e = Executors.newCachedThreadPool();
        e = new DelegatingSecurityContextExecutorService(e);
        try {
            return "hola, " + e.submit(task).get() + "!";
        } finally {
            e.shutdown();
        }
    }
```

## Modificando o cabeçalho de resposta em caso de falha na autenticacao
- para personalizar uma resposta para uma autenticação com falha, podemos implementar a interface AuthenticationEntryPoint
- e coloca-la na nossa configuração de segurança(HttpSecurity)

# Authorização (ações que o usuário pode executar no app)
- o filtro de autorização utiliza o contexto para pegar os authorities e decidir se a requisição(usuário) autenticada tem ou não autorização
- as autorizações ficam dentro da implementação da interface GrantedAuthority, que esta no user details
- um userDetails pode ter várias grantedAuthorities
- dentro da configuração de authorização, podemos utilizar o hasAnyAuthority(varargs), hasAuthority(value) ou access()
```
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http.httpBasic(Customizer.withDefaults());

        http.authorizeHttpRequests(
                c -> c.anyRequest()
                        //.hasAuthority("WRITE")
                        .hasAnyAuthority("WRITE", "READ")
        );

        return http.build();
    }
```
- o método access() é indicado para casos mais complexos, onde os outros 2 não atendem.
- por exemplo, so e permitido acesso após as 12h
```
T(java.time.LocalTime).now().isAfter(T(java.time.LocalTime).of(12, 0))
```

### use de roles
- roles é uma conjunto de autoridades que um usuário pode executar
- por exemplo admin é uma role, que podem read, write e delete
- lembrando que as roles devem começar com ROLE_, como ROLE_ADMIN, para criar ao usuario
- em seu uso, deve ignorar o prefixo ROLE_
- para definir restrições com base em roles, podem usar os seguintes métodos, hasRole(), hasAnyRole() e access()
```

        http.authorizeHttpRequests(
                c -> c.anyRequest()
                        .hasRole("ADMIN")
        );
        
        User.withUsername("jane")
                .password("12345")                
                .authorities("ROLE_MANAGER")
                .build();
```
- se usar roles("value"), na especificação do usuaŕio, podemos ignorar o ROLE_

### restringir por path
- para restringir o acesso a um determinado endpoint, utilizamos o requestMatchers(), como:
```
        http.authorizeHttpRequests(
                c -> c.requestMatchers("/hello").hasRole("ADMIN")
                        .requestMatchers("/ciao").hasRole("MANAGER")
                        .anyRequest().permitAll())
```
- sempre vamos do mais especifico para o geral, caso queira restringir um caminho e liberar os demais, começo pela restrição
- podemos referenciar a varios valores no path ou a apenas um, utilizando o corings ** para varias ou * para um, como:
```
http.authorizeHttpRequests(
                c -> c.requestMatchers("/a/**).authenticated()
                        .anyRequest().permitAll())
```
- no exemplo acima a/**, corresponde a a/qualquer coisa, qualquer quantidade de caminhos
- no exemplo a a/*, corresponde  a um caminho tipo: a/b. a/qualquer caminho
- uma outra forma é utilizar expressão regular para restringir acesso a um path. 
  - por exemplo: temos o path /{country}/{language}, somente vamos permitir acesso a paises US, CA, Uk e idioma en ou fr, caso não atenda, o usuario deverá ter uma função premium.
```
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) 
    throws Exception {
 
    http.httpBasic(Customizer.withDefaults());
 
    http.authorizeHttpRequests(
 
      c -> c.regexMatchers(".*/(us|uk|ca)+/(en|fr).*")
                .authenticated()    
            .anyRequest()           
                .hasAuthority("premium");
  
    );      
 
  }
```

## CSRF
- por default endpoints post são protejidos pelo filter csrf no spring security
- csrf é um tipo de ataque generalizado, fazendo com que os usuários executem ações indesejadas em um app web após a autenticação.
- para se proteger, envia-se um token exclusivo no header da requisição (não o token de autenticação), para operações mutantes (post, put, delete, path)
- esse token é usado pelo filter csrffilter (que intercepta todas as requisições quando a proteção csrf estiver ativa)
- o token e gerado por um componente CsrfTokenRepository, que armazena na sessão http
- o atributo aonde armazena-se o token é chamado de _csrf
- exemplo abaixo de uma requisição passando o token csrf, e também precisamos passar o id da sessão, pois a implementação padrão do csrftokenrepository, vincula o token a sessão http
```
curl -X POST   http://localhost:8080/hello 
-H 'Cookie: JSESSIONID=21ADA55E10D70BA81C338FFBB06B0206'   
-H 'X-CSRF-TOKEN: tAlE3LB_R_KN48DFlRChc…'
```
- obs: é de responsabilidade do backend enviar o token csrf ao front no momento do get
- essa abordagem e indicada quando o servidor que autentica o token, é o mesmo que gerencia as paginas
- em caso de separação entre front e backend, outra abordagem e indicada
- também podemos customizar o token csrf, e quais endpoints terão by pass dele
- aqui um exemplo:
```
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf(c -> c.ignoringRequestMatchers("/ciao"));
        http.authorizeHttpRequests(c -> c.anyRequest().permitAll());

        return http.build();
    }
```
- podemos personalizar a geração e a consulta do token, implementando a interface conforme abaixo e fazendo uso da implementação no config:
```
public class CustomCsrfTokenRepository implements CsrfTokenRepository
```
```
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf(c -> {
            c.csrfTokenRepository(csrfTokenRepository);
            c.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
        });

        http.authorizeHttpRequests(c -> c.anyRequest().permitAll());

        return http.build();
    }

```

# CORS
- compartilhamento de recursos com origiens (dominios) diferentes
- é uma restrição do navegador, não aceitar requisições para diminíos diferentes de onde ele esta hospedado
- para contornar isso existe o cors, onde podemos especificiar quais métodos ou dominios podem ser aceitos
- podemos fazer via cabeçalho da requisição ou configuração 
- abaixo um exemplo de configuração de cors
- devemos informar os verbos http, porque o corsconfiguration não possui comportamento padrão, ou seja, se não informar, não conseguiremos acessar os endpoints
```
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors(c -> {
            CorsConfigurationSource source = request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("example.com", "example.org"));
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                config.setAllowedHeaders(List.of(""));
                
                return config;
            };
            
            c.configurationSource(source);
        });
        
        http.csrf(c -> c.disable());
        http.authorizeHttpRequests(c -> c.anyRequest().permitAll());

        return http.build();
    }
```

# Authorização nivel de método
- authorização de chamada -> decide se alguem pode chamar um método com base em algumas regras de privilégios ou acessar seu retorno
- authorização filtragem -> decide o que o método pode receber de parâmetro e o que o chamador pode receber de volta

## funcionamento autorização nivel de método
- o spring utiliza aspectos
- classificamos a autorização de chamada como:
  - pré autorização -> verifica antes da chamada do método
  - pós autorização -> verifica após a execução do método (cuidado ao usar essa abordagem para métodos mutáveis, póis não seram revertidiso, mesmo com @transactional)
- para ativer tante a pre como a pos autorização apenas anotamos a classe de configuração @EnableMethodSecurity (nas versões anteriores pre e pos autorização não eram habilitadas com essa anotação)
- para utilizar a autorização sobre método, podemos anotar:
```
@Service
public class NameService {
 
  @PreAuthorize("hasAuthority('write')")
  public String getName() {
    return "Fantastico";
  }
}
```
- recapitulação:
```
hasAnyAuthority()—Especifica várias autoridades. O usuário deve ter pelo menos uma dessas autoridades para chamar o método.
hasRole()—Especifica uma função que um usuário deve ter para chamar o método.
hasAnyRole()—Especifica várias funções. O usuário deve ter pelo menos um deles para chamar o método.
```
- uma observação ao @PostAuthorize, ele não proteje o método e sim o seu retorno, que utilizamos para a regra de exibir ou não ao chamador.
- para regras mais complexas, podemos utilizar o hasPermissions, que necessitaŕia de uma implementação do PerimssionEvaluator
- abaixo está um exemplo (diferente do aplicado no projeto autorizacao-method), usando targetId
```
@Component
public class DocumentsPermissionEvaluator
  implements PermissionEvaluator {
 
  private final DocumentRepository documentRepository;
 
  // Omitted constructor
 
  @Override
  public boolean hasPermission(Authentication authentication,
                               Object target,
                               Object permission) {
    return false;
  }
 
  @Override
  public boolean hasPermission(Authentication authentication,
                                 Serializable targetId,
                                 String targetType,
                                 Object permission) {
 
    String code = targetId.toString();
    Document document = documentRepository.findDocument(code);
 
    String p = (String) permission;
 
 
    boolean admin =
           authentication.getAuthorities()
              .stream()
              .anyMatch(a -> a.getAuthority().equals(p));
 
     return admin ||
       document.getOwner().equals(
         authentication.getName());
  }
}

@Service
public class DocumentService {
 
  private final DocumentRepository documentRepository;
 
  // Omitted contructor
 
  @PreAuthorize
   ("hasPermission(#code, 'document', 'ROLE_admin')")
  public Document getDocument(String code) {
    return documentRepository.findDocument(code);
  }
}
```

- ultimo ponto, spring aceita vários permissionEvaluator, mas acata o ultimo configurado (deve-se ajustar quando possui mutiplos targets)

# Pre filtragem e pos filtragem
- diferente do ponto acima, a filtragem não restringe a execução do método, ele apenas filtra os parâmetros recebidos ou valores retornados, com base em sua regra
- lembrando que essa abordagem é aplica-se em métodos que recebe uma lista/array ou retorna uma lista/array no caso de pos filtragem
- para usar dentro de uma query, a spel de segurança, temos que add
```
    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
// https://mvnrepository.com/artifact/org.springframework.security/spring-security-data
implementation group: 'org.springframework.security', name: 'spring-security-data', version: '6.1.3'


    @Query("Select p from Product p where p.owner =?#{authentication.name} and p.describe like %:text%")
    List<Product> findProductByDescribeContains(String text);
```

# Openid Connect e OAuth2

## oauth2
- oauth2 é um especificação que informa como seprar as responsabilidades de autenticação em um sistema.
- dessa forma, vários aplicativos podem utilizar u outro aplicativo que implementa a autenticação, ajudando os usuários a se autenticarem mais rapidamente,
- mantendo seus dados mais seguros e minimizando os custos de implmentação nos aplicativos.

### entidades participantes do oauth2
- user -> pessoa que usa o app, geralmente usam um frontend, que chamamo de client
- client -> app que chamada o backend e precisa de autenticação e autorização, o client pode der um app movel, desktop ou outro backend (nesse caso não precisa do user)
- resources server -> um app backend que recebe as requisições enviadas pelo client e as autoriza, este faz uso do token para autorizar a utilização dos seus recursos
- authenticarion server 
  - um app que implementa autenticação do usuário e o aplicativo que ele usa, também o armazenamento seguro de credenciais
  - emissão de tokens para comprovar a autenticação, afim de acessar recursos protegidos por um backend

### classificação dos tokens
- opaco -> token não contem dados, para implementar a autorização, o servidor de recursos chama o servidor de autorização para maiores detalhes, essa chamada tem o nome de introspecção
```
curl -X POST 'http://localhost:8080/oauth2/introspect?
[CA]token=iED8-…' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
```
- não opaco -> armazenam dados e disponibilizam imediatamente ao backend para impelementação da autorização. Tokens não opacos são conhecidos como jwt (json web token)


#### tokens não opacos
- são como documentos assinados
- contem detalhes necessários para o servidor de recursos aplicar as restrições de autorização
- e uma assinatura para validar sua autenticidade

#### grant types
- são formas pelo qual um client obtém um token 

#### authorization code grant type
- usamos esse tipo de concessão quando nosso  app precisa autenticar o usuário
- após o client se autenticadar, junto com sua sua credencial e do user, recebe um code
- esse code, junto com a credencial do client, e enviado novamente para pegar o token
- para deixar mais seguro, no retorno do code, podemos usar a chave de prova ou PKCE
- é um aprimoramento adicionado ao fluxo de código de autorização para torna-lo mais seguro.

##### funcionamento do pkce
- client gera um valor qualquer, conhecido como verificador
- depois aplica uma função hash sobre esse valor
- e etapa de login, o client manda resultado da função hash e o algoritimo usado (desafio)
- depois enviada junto ao code (ja recebido), o verificador (valor nao aplicado algoritimo) , para confirmar que é o mesmo client que fez o login do user
```
//verificador
SecureRandom secureRandom = new SecureRandom();
byte [] code = new byte[32];
secureRandom.nextBytes(code);
String codeVerifier = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(code);
        
//desafio
MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
 
byte [] digested = messageDigest.digest(verifier.getBytes());
String codeChallenge = Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(digested);     
```

#### grant type client
- quando um backend precisa chamar outro backend


## openid connect (OICD)
- é um protocolo construído sobre a especificaçao oauth2

## Principais componentes para configurar um authorization server
- filtro de configuração para terminais de protocolo (configurações específicas)
- filtros de configuração de autenticação (cors, csrf, spring security por ex)
- componentes de gerenciamento de detalhes do usuário (userDetailsService)
- gerenciamento de detalhes do client (registered client repository, client - app cliente)
- gerenciamento de chaves (chave publica e privada)
- exemplo de uma configuração do servidor de autorização no spring
```
package com.github.authorizationserverv1;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class SecurityConfig {
    
    //precisamos definir uma ordem de configuração, pois são muitos filtros, este configura o endpoint para o usuario logar
    @Bean
    @Order(1)
    public SecurityFilterChain addFilterChain(final HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        
        httpSecurity.exceptionHandling(e -> e.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
        ));
        
        return httpSecurity.build();
    }
    
    //este configura as rotas liberadas ou que precisam ser autenticadas
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
        http.formLogin(Customizer.withDefaults());
        
        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService(final PasswordEncoder passwordEncoder) {
        final UserDetails user = User.withUsername("bill")
                .password(passwordEncoder.encode("1234"))
                .roles("USER")
                .build();
        
        return new InMemoryUserDetailsManager(user);
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    //simular ao userdetailsSrvice e userDetails, para o usuario, mas este é para o client  (app cliente)
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient2 =
                RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId("client2")
                        .clientSecret("secret")
                        .clientAuthenticationMethod(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(
                                AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(
                                AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizationGrantType(
                                AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("https://www.manning.com/authorized")
                        .scope(OidcScopes.OPENID)
                        .build();
        
        RegisteredClient registeredClient =
                RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId("client")
                        .clientSecret("secret")
                        .clientAuthenticationMethod(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(
                                AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("https://www.manning.com/authorized")
                        .scope(OidcScopes.OPENID)
                        .build();

        return new InMemoryRegisteredClientRepository(registeredClient, registeredClient2);
    }
    // ideal que as chaves ficam externas a aplicação e consultaadas
    @Bean
    public JWKSource<SecurityContext> jwkSource()
            throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    //este para customizar todos os caminhos do servidor de autorização, se criarmos apenas, os endpotins receberão alguns padrões
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}

```

## um pouco sobre o jose
```
O JOSE (Javascript Object Signing and Encryption) é um framework para segurança em APIs REST utilizando JWT, JWS e JWE para criptografia e assinatura de conteúdo JSON.

Ele pode ser utilizado com OAuth2 no Spring Boot para autenticação e autorização.

Alguns pontos:

O JWT (JSON Web Token) é um padrão RFC para tokens de acesso compactos e autocontidos.
O token JWT contém claims que carregam informações como escopo, expiração, roles.
É assinado digitalmente para garantir integridade.
O Spring Security OAuth2 integra com JWT para emitir tokens após autenticação.
Tokens JWT são retornados para o cliente e utilizados para autenticar requisições seguintes.
O cliente envia o token no header Authorization: Bearer [jwt].
Os endpoints são protegidos via @EnableGlobalMethodSecurity com pré-autorização.
As roles/escopos dentro do token são utilizados para autorização.


JWS e JWE são especificações relacionadas ao JOSE que definem formatos para assinatura e criptografia de conteúdo JSON respectivamente:

JWS (JSON Web Signature): Define um formato para assinar digitalmente conteúdo JSON serializado. Usado para verificar integridade e autenticidade.
JWE (JSON Web Encryption): Especifica uma forma de criptografar conteúdo JSON usando algoritmos simétricos e assimétricos. Ideal para segurança em trânsito.

```

## para descobrir os endpotins expostos pelo servidor de autorização, afim de solicitar o token?
- apenas chame o endpoint http://localhost:8080/.well-known/openid-configuration
- exemplo para chamar o endpoint de autorização (authentication code):
  - http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://www.manning.com/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256
- no exemplo acima, estamos usando o pkce, chave de desafio, caso queira desabilitar:
```
RegisteredClient registeredClient = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("client")
        // …
        .clientSettings(ClientSettings.builder()
            .requireProofKey(false)
            .build()) 
        .build();
```

## revogação de token
```
curl -X POST 'http://localhost:8080/oauth2/revoke?
[CA]token=N7BruErWm-44-…' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' 
```

## servidor de recursos em detalhes
- o servidor de recursos precisa conhecer a url http://localhost:9090/oauth2/jwks (que podemos ve-la aqui http://localhost:8080/.well-known/openid-configuration), afim de pegar a chave publica pra validar o token
- pode-se fazer uso do endpoint de introspecção
  - quando precisamos de mais detalhes que não esteja no token ou revogar ele, precisamos consultar o servidor de autorização (indicado para token opaco)
- diferença entre a configuração para o token opaco e jwt
- opaco
```
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(
                c -> c.opaqueToken(
                        o -> o.introspectionUri(introspectionUri)
                                .introspectionClientCredentials(
                                        resourceServerClientID,
                                        resourceServerSecret)
                )
        );

        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }
```
- jwt
```
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(c -> c.jwt(
                j -> j.jwkSetUri(keySetUri)
                        .jwtAuthenticationConverter(converter)
        ));

        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }
```

## multitenancy
- quando o servidor de recurso, depende de vários servidores de autorização
- para esses casos podemos fazer do authenticatioManagerResolver 
  - ele tem a função similar do authentication manager que delega para o authentication provider 
- abaixo um exemplo utilizando dois servidores
```
@Configuration
public class ProjectConfig {
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) 
    throws Exception {
    
    http.oauth2ResourceServer(
      j -> j.authenticationManagerResolver(
               authenticationManagerResolver())
    );
    http.authorizeHttpRequests(
      c -> c.anyRequest().authenticated()
    );
    return http.build();
  }
  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> 
    [CA]authenticationManagerResolver() {
    
    var a = new JwtIssuerAuthenticationManagerResolver(
        "http://localhost:7070", 
        "http://localhost:8080");
    return a;
  }
}
```
- abaixo um exemplo mais complexo, dependendo do valor do header da requisição, o token e validado em um servidor jwt ou opaco
```
@Configuration
public class ProjectConfig { 

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) 
    throws Exception {
    
    http.oauth2ResourceServer(
      j -> j.authenticationManagerResolver(
                authenticationManagerResolver(
                  jwtDecoder(), 
                  opaqueTokenIntrospector()
                ))
    );
    http.authorizeHttpRequests(
      c -> c.anyRequest().authenticated()
    );
    return http.build();
  }
  
  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> 
    [CA]authenticationManagerResolver(
        JwtDecoder jwtDecoder, 
        OpaqueTokenIntrospector opaqueTokenIntrospector
    ) {
        
    AuthenticationManager jwtAuth = new ProviderManager(
      new JwtAuthenticationProvider(jwtDecoder)    
    );
    AuthenticationManager opaqueAuth = new ProviderManager(
      new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector)
    );
    return (request) -> {
      if ("jwt".equals(request.getHeader("type"))) {
         return jwtAuth;
      } else {
         return opaqueAuth;
      }
    };
  }
  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder
            .withJwkSetUri("http://localhost:7070/oauth2/jwks")
            .build();
  }
  @Bean
  public OpaqueTokenIntrospector opaqueTokenIntrospector() {
    return new SpringOpaqueTokenIntrospector(
       "http://localhost:6060/oauth2/introspect",
       "client", "secret");
  }
}
```

## um pouco mais de explicação da chave publica e privada

```
As chaves pública e privada são utilizadas no OAuth 2.0 para assinar e verificar tokens, proporcionando segurança ao fluxo de autorização. O uso delas ocorre da seguinte maneira:

O servidor de autorização possui um par de chaves pública-privada para assinatura de tokens.
A chave privada é mantida em sigilo pelo servidor e usada para assinar os tokens JWT enviados ao cliente.
A chave pública é compartilhada com os clientes e permite que eles verifiquem a assinatura do token.
Quando o cliente recebe um token assinado, ele valida a assinatura usando a chave pública do servidor.
Isso garante que o token foi realmente emitido pelo servidor legítimo e não foi adulterado.
Como somente o servidor tem acesso à chave privada, um invasor não consegue criar tokens válidos e assinados.
Se o token foi modificado ou a assinatura não bate com a chave pública, o cliente o rejeita.
Desta forma, a identidade do servidor é validada e a integridade do token é verificada.
O OAuth 2.0 requer o uso de criptografia assimétrica e assinaturas digitais para maior segurança.
As chaves também podem ser rotacionadas periodicamente para maior proteção contra ataques.
Portanto, as chaves pública-privada são peças fundamentais na arquitetura de segurança do OAuth 2.0.
```
