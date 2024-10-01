package com.luv2code.springboot.cruddemo.security;


import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // Indica que esta classe é uma classe de configuração do Spring.
public class DemoSecurityConfig {

    //Criando suporte para JDBC, ou seja, nao será necessário definr usuário dentro do código, eles ficarão armazenados
    //no Bando de Dados.
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {

        //Aqui, um objeto JdbcUserDetailsManager é criado usando o DataSource fornecido. 
        //JdbcUserDetailsManager é uma implementação de UserDetailsManager que usa JDBC 
        //para acessar informações de usuários no banco de dados de forma automática;
        JdbcUserDetailsManager customJdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
         
        //Este método configura a consulta SQL que será usada para buscar os detalhes do usuário 
        //(nome de usuário, senha e status ativo) a partir da tabela members. 
        //O ? é um placeholder para o nome de usuário que será fornecido em tempo de execução.
        customJdbcUserDetailsManager.setUsersByUsernameQuery("SELECT user_id, pw, ACTIVE FROM members WHERE user_id=?");

        //Este método configura a consulta SQL para buscar as autoridades (ou roles) do usuário a partir 
        //da tabela roles. A interrogação (?) é um placeholder para o nome de usuário.
        customJdbcUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id, role FROM roles WHERE user_id=?");

        // Retorna o customJdbcUserDetailsManager configurado como um bean gerenciado pelo Spring
        return customJdbcUserDetailsManager;
    }

    @Bean // Define um bean que será gerenciado pelo Spring. Um bean é um objeto que é instanciado, montado e gerenciado pelo Spring IoC container.
    public SecurityFilterChain filterChain(HttpSecurity https) throws Exception {
    
        // Configura a autorização de requisições HTTP. O método authorizeHttpRequests() permite definir regras de segurança para diferentes endpoints.
        https.authorizeHttpRequests(configurer ->
            configurer
            // Permite requisições GET para "api/employees" apenas para usuários com o papel "EMPLOYEE".
            // HttpMethod.GET especifica que a regra se aplica a requisições GET.
            // "api/employees" é o endpoint que está sendo protegido.
            // hasRole("EMPLOYEE") indica que apenas usuários com o papel "EMPLOYEE" podem acessar este endpoint.
            .requestMatchers(HttpMethod.GET, "api/employees").hasRole("EMPLOYEE")
        
            // Permite requisições GET para qualquer subcaminho de "api/employees" apenas para usuários com o papel "EMPLOYEE".
            // O "**" é um wildcard que corresponde a qualquer sequência de caracteres. Por exemplo, "api/employee/1" referente
            // ao id 1;
            .requestMatchers(HttpMethod.GET, "api/employees/**").hasRole("EMPLOYEE")
            
            // Permite requisições POST para "api/employees" apenas para usuários com o papel "MANAGER".
            // HttpMethod.POST especifica que a regra se aplica a requisições POST.
            .requestMatchers(HttpMethod.POST, "api/employees").hasRole("MANAGER")
            
            // Permite requisições PUT para qualquer subcaminho de "api/employees" apenas para usuários com o papel "MANAGER".
            // HttpMethod.PUT especifica que a regra se aplica a requisições PUT.
            .requestMatchers(HttpMethod.PUT, "api/employees/**").hasRole("MANAGER")
            
            // Permite requisições DELETE para qualquer subcaminho de "api/employees" apenas para usuários com o papel "ADMIN".
            // HttpMethod.DELETE especifica que a regra se aplica a requisições DELETE.
            .requestMatchers(HttpMethod.DELETE, "api/employees/**").hasRole("ADMIN")
            );
            
            // Configura a autenticação HTTP básica. httpBasic() é um método que configura a autenticação básica, onde o navegador solicita um nome de usuário e senha.
            // Customizer.withDefaults() aplica as configurações padrão para a autenticação básica.
        https.httpBasic(Customizer.withDefaults());
            
            // Desabilita a proteção CSRF (Cross-Site Request Forgery). csrf() retorna um objeto CsrfConfigurer que permite configurar a proteção CSRF.
            // csrf.disable() desabilita essa proteção. Isso pode ser útil em APIs RESTful onde o CSRF não é uma preocupação, mas deve ser usado com cautela.
        https.csrf(csrf -> csrf.disable());
            
            // Constrói e retorna o objeto SecurityFilterChain configurado. build() finaliza a configuração e retorna uma instância de SecurityFilterChain.
        return https.build();
    }

}

                /*
                @Bean // Define um bean que será gerenciado pelo Spring (no caso, o método abaixo).
                public InMemoryUserDetailsManager userDetailsManager() {
                    
                    // Cria um usuário com nome de usuário "john", senha "test123" (sem codificação) e papel "EMPLOYEE".
                    UserDetails john = User.builder()
                                                .username("john")
                                                .password("{noop}test123") // {noop} indica que a senha não está codificada.
                                                .roles("EMPLOYEE")
                                                .build();
                    
                    // Cria um usuário com nome de usuário "mary", senha "test123" (sem codificação) e papéis "EMPLOYEE" e "MANAGER".
                    UserDetails mary = User.builder()
                                                .username("mary")
                                                .password("{noop}test123")
                                                .roles("EMPLOYEE", "MANAGER")
                                                .build();
            
                    // Cria um usuário com nome de usuário "susan", senha "test123" (sem codificação) e papéis "EMPLOYEE", "MANAGER" e "ADMIN".
                    UserDetails susan = User.builder()
                                                .username("susan")
                                                .password("{noop}test123")
                                                .roles("EMPLOYEE", "MANAGER", "ADMIN")
                                                .build();
                    
                    //cria um arraylist do usuários definidos acima;
                    List<UserDetails> users = new ArrayList <UserDetails>();
                    users.add(john);
                    users.add(mary);
                    users.add(susan);
            
                    
                    // Retorna um InMemoryUserDetailsManager com os usuários criados.
                    return new InMemoryUserDetailsManager(users);
            
                    //ESSAS CONFIGURAÇÕES TEM MAIOR PRIORIDADE QUE O ARQUIVO DE CONFIGURAÇÕES .properties, OU SEJA,
                    //AS CONFIGURAÇÕES DE USUÁRIO QUE ESTÃO LÁ SERÃO IGNORADAS E AS DESTE ARQUIVO IRÃO FUNCIONAR;
                }
                 */