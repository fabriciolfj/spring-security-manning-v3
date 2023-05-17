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
- caso utilize um shema diferente do padrão jdbcuserdetailsmanager, podemos personalizar, conforme demonstrado abaixo:
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
- utilizados para erar um tipo de chave, que está é utilizada para algum algoritmo de criptografia ou hash.

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