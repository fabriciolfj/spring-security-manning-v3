# Spring security (spring framework 6)

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

``
