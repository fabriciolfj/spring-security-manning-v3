# Spring security (spring framework 6)

- quando cria-se um projeto spring, o mesmo vem com algumas configurações padrões, dependendo das dependências inseridas
- no caso do spring security, ja temos os seguintes componentes criados e envolvidos:

#### Authentication filter
- delega a autenticação para o authentication manager
- com base na resposta do authentication manager, configura o contexto de segurança

#### Authentication manager
- utiliza um provedor de autenticação para processar a autenticação

#### Authentication provider
- possui a lógica de autenticação
- costuma-se utilizar o UserDetailsService e o password encoder

#### UserDetailsService
- implementa a responsabilidade de gerenciamento do usuário

#### Password encoder
-implementa o gerenciamento de senha

#### Security context
- mantem os dados de autenticação apõs o processo de autenticação.
