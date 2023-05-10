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
