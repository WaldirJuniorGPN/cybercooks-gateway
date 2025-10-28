# Gateway - API Gateway do Ecossistema Bytecooks

Ponto único de entrada para todos os microsserviços do ecossistema Bytecooks, responsável por roteamento inteligente, balanceamento de carga, autenticação e aplicação de políticas cross-cutting.

## Visão Geral

O API Gateway atua como uma fachada que unifica o acesso aos microsserviços, abstraindo a complexidade da arquitetura distribuída. Ele intercepta todas as requisições externas, aplica regras de segurança, realiza roteamento dinâmico através do Eureka Server e adiciona funcionalidades transversais como logging, rate limiting e circuit breaker.

## Tecnologias Utilizadas

- **Java 17**
- **Spring Boot 3.5.7**
- **Spring Cloud Gateway** - Roteamento reativo e dinâmico
- **Spring Cloud Netflix Eureka Client** - Service Discovery
- **Spring Cloud LoadBalancer** - Balanceamento de carga client-side
- **Spring WebFlux** - Programação reativa (base do Gateway)

## Conceitos Importantes

### O que é um API Gateway?

Um API Gateway é um servidor que funciona como ponto de entrada único (single entry point) para um conjunto de microsserviços. Ele recebe todas as requisições da API, roteia-as para os serviços apropriados, agrega os resultados e retorna a resposta adequada ao cliente.

### Por Que Usar API Gateway?

**Problemas que Resolve:**

1. **Complexidade do Cliente**: Sem Gateway, clientes precisariam conhecer e se comunicar diretamente com múltiplos microsserviços
2. **Cross-Cutting Concerns**: Funcionalidades como autenticação, logging e rate limiting ficariam duplicadas em cada serviço
3. **Mudanças na Arquitetura**: Alterações na estrutura de microsserviços afetariam diretamente os clientes
4. **Segurança**: Expor múltiplos endpoints aumenta a superfície de ataque

**Benefícios:**

- **Desacoplamento**: Clientes não precisam conhecer a localização física dos serviços
- **Simplificação**: Interface unificada e consistente
- **Segurança Centralizada**: Autenticação e autorização em um único ponto
- **Monitoramento**: Visibilidade centralizada de todas as requisições
- **Resiliência**: Circuit breaker e fallbacks protegem contra falhas em cascata
- **Performance**: Cache, compressão e otimizações centralizadas

### Spring Cloud Gateway vs Zuul

O Spring Cloud Gateway é a evolução moderna do Zuul, construído sobre Spring WebFlux (reativo) ao invés de Servlet API (bloqueante). Principais vantagens:

- **Não-bloqueante**: Melhor performance com menos threads
- **Reativo**: Suporta backpressure e processamento assíncrono
- **Predicates e Filters**: Sistema poderoso e flexível de roteamento
- **Moderno**: Mantido ativamente pelo time do Spring

## Pré-requisitos

- JDK 17 ou superior
- Maven 3.6+
- Eureka Server rodando (porta 8761)
- IDE de sua preferência (IntelliJ IDEA, Eclipse, VS Code)

## Instalação e Execução

### Clonar o Repositório

```bash
git clone git@github.com:WaldirJuniorGPN/cybercooks-gateway.git
cd gateway
```

### Compilar o Projeto

```bash
mvn clean install
```

### Executar a Aplicação

```bash
mvn spring-boot:run
```

O Gateway estará disponível em `http://localhost:8082`

## Configuração

### application.yml

```yaml
spring:
  application:
    name: gateway
  cloud:
    gateway:
      discovery:
        locator:
          enabled: true
          lower-case-service-id: true
      routes:
        - id: pagamentos-service
          uri: lb://pagamentos
          predicates:
            - Path=/api/v1/pagamentos/**
          filters:
            - StripPrefix=0
            
        - id: pedidos-service
          uri: lb://pedidos-service
          predicates:
            - Path=/api/v1/pedidos/**
          filters:
            - StripPrefix=0

server:
  port: 8082

eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
    register-with-eureka: true
    fetch-registry: true
  instance:
    prefer-ip-address: true
    instance-id: ${spring.application.name}:${spring.application.instance_id:${random.value}}
```

### Explicação Detalhada das Configurações

#### Discovery Locator

```yaml
spring.cloud.gateway.discovery.locator.enabled: true
```
Habilita roteamento automático baseado em serviços registrados no Eureka. Permite acessar qualquer serviço usando: `http://gateway:8082/{service-name}/**`

```yaml
spring.cloud.gateway.discovery.locator.lower-case-service-id: true
```
Converte nomes de serviços para lowercase nas URLs (pagamentos ao invés de PAGAMENTOS).

#### Rotas Customizadas

Cada rota define:
- **id**: Identificador único da rota
- **uri**: Destino (lb:// indica load balancing via Eureka)
- **predicates**: Condições que a requisição deve atender
- **filters**: Transformações aplicadas à requisição/resposta

**Predicates Comuns:**
- `Path`: Corresponde ao caminho da URL
- `Method`: Corresponde ao método HTTP (GET, POST, etc.)
- `Header`: Corresponde a headers específicos
- `Query`: Corresponde a query parameters

**Filters Comuns:**
- `StripPrefix`: Remove N partes do path antes de enviar ao serviço
- `AddRequestHeader`: Adiciona header à requisição
- `AddResponseHeader`: Adiciona header à resposta
- `RewritePath`: Reescreve o path da requisição

### Classe Principal

```java
package br.com.bytecooks.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
```

A anotação `@EnableDiscoveryClient` integra o Gateway com o Eureka Server para descoberta dinâmica de serviços.

## Exemplos de Roteamento

### Roteamento Básico

```yaml
routes:
  - id: pagamentos-route
    uri: lb://pagamentos
    predicates:
      - Path=/api/v1/pagamentos/**
```

**Como funciona:**
1. Cliente faz requisição: `GET http://gateway:8082/api/v1/pagamentos/123`
2. Gateway consulta Eureka pelo serviço "pagamentos"
3. Eureka retorna instâncias disponíveis (ex: pagamentos1:8080, pagamentos2:8081)
4. LoadBalancer escolhe uma instância (round-robin por padrão)
5. Gateway encaminha: `GET http://pagamentos1:8080/api/v1/pagamentos/123`

### Roteamento com Reescrita de Path

```yaml
routes:
  - id: pagamentos-route
    uri: lb://pagamentos
    predicates:
      - Path=/payment-api/**
    filters:
      - RewritePath=/payment-api/(?<segment>.*), /api/v1/pagamentos/${segment}
```

**Exemplo:**
- Requisição: `GET /payment-api/123`
- Encaminhado como: `GET /api/v1/pagamentos/123`

### Roteamento por Método HTTP

```yaml
routes:
  - id: pagamentos-post
    uri: lb://pagamentos
    predicates:
      - Path=/api/v1/pagamentos/**
      - Method=POST,PUT
    filters:
      - AddRequestHeader=X-Request-Source, Gateway
```

### Roteamento por Header

```yaml
routes:
  - id: pagamentos-admin
    uri: lb://pagamentos-admin
    predicates:
      - Path=/api/v1/pagamentos/**
      - Header=X-User-Role, ADMIN
```

## Filters Customizados

### Global Filter para Logging

```java
package br.com.bytecooks.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class LoggingGlobalFilter implements GlobalFilter, Ordered {
    
    private static final Logger logger = LoggerFactory.getLogger(LoggingGlobalFilter.class);
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().toString();
        
        logger.info("Requisição recebida: {} {}", method, path);
        
        long startTime = System.currentTimeMillis();
        
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            long duration = System.currentTimeMillis() - startTime;
            int statusCode = exchange.getResponse().getStatusCode().value();
            logger.info("Resposta enviada: {} {} - Status: {} - Tempo: {}ms", 
                method, path, statusCode, duration);
        }));
    }
    
    @Override
    public int getOrder() {
        return -1; // Executa antes dos outros filters
    }
}
```

**Observação Importante**: Embora este código funcione, ele viola algumas das suas preferências de boas práticas:

1. **Classe com mais de 50 linhas**: Se adicionar mais lógica, rapidamente ultrapassará
2. **Logging direto**: Poderia ser extraído para um componente de logging
3. **Responsabilidade mista**: Loga request E response

**Refatoração sugerida** (aplicando Object Calisthenics):

```java
@Component
public class LoggingGlobalFilter implements GlobalFilter, Ordered {
    
    private final RequestLogger requestLogger;
    private final ResponseLogger responseLogger;
    
    public LoggingGlobalFilter(RequestLogger requestLogger, ResponseLogger responseLogger) {
        this.requestLogger = requestLogger;
        this.responseLogger = responseLogger;
    }
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        RequestInfo requestInfo = RequestInfo.from(exchange.getRequest());
        requestLogger.log(requestInfo);
        
        Instant startTime = Instant.now();
        
        return chain.filter(exchange)
            .then(Mono.fromRunnable(() -> 
                responseLogger.log(ResponseInfo.from(exchange.getResponse(), requestInfo, startTime))
            ));
    }
    
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
```

### GatewayFilter para Autenticação

```java
package br.com.bytecooks.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationGatewayFilterFactory 
        extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {
    
    private final TokenValidator tokenValidator;
    
    public AuthenticationGatewayFilterFactory(TokenValidator tokenValidator) {
        super(Config.class);
        this.tokenValidator = tokenValidator;
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest()
                .getHeaders()
                .getFirst("Authorization");
            
            if (tokenValidator.isValid(token)) {
                return chain.filter(exchange);
            }
            
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }
    
    public static class Config {
        // Configurações do filter, se necessário
    }
}
```

**Uso na configuração:**

```yaml
routes:
  - id: pagamentos-secure
    uri: lb://pagamentos
    predicates:
      - Path=/api/v1/pagamentos/**
    filters:
      - Authentication
```

## Balanceamento de Carga

O Spring Cloud LoadBalancer é usado automaticamente quando você usa `lb://` no URI.

### Estratégias de Balanceamento

#### Round Robin (Padrão)

```java
// Não precisa configuração adicional, é o comportamento padrão
```

#### Random

```java
package br.com.bytecooks.gateway.config;

import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.loadbalancer.core.RandomLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ReactorLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class LoadBalancerConfig {
    
    @Bean
    public ReactorLoadBalancer<ServiceInstance> randomLoadBalancer(
            Environment environment,
            LoadBalancerClientFactory loadBalancerClientFactory) {
        
        String serviceId = environment.getProperty(LoadBalancerClientFactory.PROPERTY_NAME);
        
        return new RandomLoadBalancer(
            loadBalancerClientFactory.getLazyProvider(serviceId, ServiceInstanceListSupplier.class),
            serviceId
        );
    }
}
```

#### Customizado (Baseado em Peso)

```java
public class WeightedLoadBalancer implements ReactorServiceInstanceLoadBalancer {
    
    private final ServiceInstanceListSupplier serviceInstanceListSupplier;
    private final String serviceId;
    
    public WeightedLoadBalancer(
            ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider,
            String serviceId) {
        this.serviceInstanceListSupplier = serviceInstanceListSupplierProvider.getIfAvailable();
        this.serviceId = serviceId;
    }
    
    @Override
    public Mono<Response<ServiceInstance>> choose(Request request) {
        return serviceInstanceListSupplier.get(request)
            .next()
            .map(this::selectInstanceByWeight);
    }
    
    private Response<ServiceInstance> selectInstanceByWeight(List<ServiceInstance> instances) {
        // Lógica de seleção baseada em peso
        // Pode usar metadata das instâncias para determinar pesos
        return new DefaultResponse(instances.get(0));
    }
}
```

## Circuit Breaker e Resiliência

### Adicionar Resilience4j

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-circuitbreaker-reactor-resilience4j</artifactId>
</dependency>
```

### Configurar Circuit Breaker

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: pagamentos-resilient
          uri: lb://pagamentos
          predicates:
            - Path=/api/v1/pagamentos/**
          filters:
            - name: CircuitBreaker
              args:
                name: pagamentosCircuitBreaker
                fallbackUri: forward:/fallback/pagamentos

resilience4j:
  circuitbreaker:
    instances:
      pagamentosCircuitBreaker:
        register-health-indicator: true
        sliding-window-size: 10
        minimum-number-of-calls: 5
        permitted-number-of-calls-in-half-open-state: 3
        automatic-transition-from-open-to-half-open-enabled: true
        wait-duration-in-open-state: 10s
        failure-rate-threshold: 50
        event-consumer-buffer-size: 10
```

### Endpoint de Fallback

```java
package br.com.bytecooks.gateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/fallback")
public class FallbackController {
    
    @GetMapping("/pagamentos")
    public ResponseEntity<ErrorResponse> pagamentosFallback() {
        ErrorResponse error = new ErrorResponse(
            "Serviço de pagamentos temporariamente indisponível",
            "Por favor, tente novamente em alguns instantes",
            HttpStatus.SERVICE_UNAVAILABLE.value()
        );
        
        return ResponseEntity
            .status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(error);
    }
}

record ErrorResponse(String message, String details, int status) {}
```

**Observação**: O uso de `record` aqui é apropriado e segue boas práticas modernas do Java.

## Rate Limiting

### Configurar Rate Limiter

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: pagamentos-rate-limited
          uri: lb://pagamentos
          predicates:
            - Path=/api/v1/pagamentos/**
          filters:
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10  # tokens por segundo
                redis-rate-limiter.burstCapacity: 20  # capacidade máxima
                redis-rate-limiter.requestedTokens: 1 # tokens por requisição
                key-resolver: "#{@userKeyResolver}"
```

### Key Resolver Customizado

```java
package br.com.bytecooks.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {
    
    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest()
                .getHeaders()
                .getFirst("X-User-Id");
            
            return Mono.just(userId != null ? userId : "anonymous");
        };
    }
    
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String ipAddress = exchange.getRequest()
                .getRemoteAddress()
                .getAddress()
                .getHostAddress();
            
            return Mono.just(ipAddress);
        };
    }
}
```

**Nota**: Para Rate Limiting funcionar, você precisa do Redis:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis-reactive</artifactId>
</dependency>
```

## CORS Configuration

```java
package br.com.bytecooks.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {
    
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = createCorsConfiguration();
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        
        return new CorsWebFilter(source);
    }
    
    private CorsConfiguration createCorsConfiguration() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(List.of("http://localhost:3000", "https://bytecooks.com.br"));
        corsConfig.setMaxAge(3600L);
        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(List.of("*"));
        corsConfig.setAllowCredentials(true);
        
        return corsConfig;
    }
}
```

**Refatoração aplicando SRP**: Observe que separei a criação da configuração CORS em um método privado. Isso melhora a legibilidade e facilita testes.

## Monitoramento e Observabilidade

### Actuator Endpoints

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,gateway
  endpoint:
    health:
      show-details: always
    gateway:
      enabled: true
```

**Endpoints Disponíveis:**
- `GET /actuator/health` - Status de saúde
- `GET /actuator/gateway/routes` - Lista todas as rotas configuradas
- `GET /actuator/gateway/routes/{id}` - Detalhes de uma rota específica
- `POST /actuator/gateway/refresh` - Recarrega configurações
- `POST /actuator/gateway/routes/{id}` - Cria/atualiza rota dinamicamente
- `DELETE /actuator/gateway/routes/{id}` - Remove rota

### Métricas Customizadas

```java
package br.com.bytecooks.gateway.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class MetricsGlobalFilter implements GlobalFilter, Ordered {
    
    private final MeterRegistry meterRegistry;
    
    public MetricsGlobalFilter(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        String method = exchange.getRequest().getMethod().name();
        
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            int statusCode = exchange.getResponse().getStatusCode().value();
            
            Counter.builder("gateway.requests")
                .tag("path", path)
                .tag("method", method)
                .tag("status", String.valueOf(statusCode))
                .register(meterRegistry)
                .increment();
        }));
    }
    
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
```

## Segurança

### Integração com OAuth2/JWT

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.bytecooks.com.br/realms/bytecooks
          jwk-set-uri: https://auth.bytecooks.com.br/realms/bytecooks/protocol/openid-connect/certs
```

```java
package br.com.bytecooks.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/api/v1/public/**").permitAll()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt()
            )
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .build();
    }
}
```

### Headers de Segurança

```yaml
spring:
  cloud:
    gateway:
      default-filters:
        - SecureHeaders
```

```java
package br.com.bytecooks.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class SecureHeadersGatewayFilterFactory 
        extends AbstractGatewayFilterFactory<Object> {
    
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> chain.filter(exchange).then(
            exchange.getResponse().beforeCommit(() -> {
                HttpHeaders headers = exchange.getResponse().getHeaders();
                headers.add("X-Content-Type-Options", "nosniff");
                headers.add("X-Frame-Options", "DENY");
                headers.add("X-XSS-Protection", "1; mode=block");
                headers.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
                return null;
            })
        );
    }
}
```

## Arquitetura do Ecossistema

```
                    ┌─────────────────────┐
                    │   Clientes          │
                    │  (Web/Mobile/API)   │
                    └──────────┬──────────┘
                               │
                               │ HTTPS
                               ▼
                    ┌─────────────────────┐
                    │   API Gateway       │
                    │   (porta 8082)      │
                    │                     │
                    │ ✓ Roteamento        │
                    │ ✓ Autenticação      │
                    │ ✓ Rate Limiting     │
                    │ ✓ Circuit Breaker   │
                    │ ✓ Logging           │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
         ┌───────────┐  ┌───────────┐  ┌───────────┐
         │Pagamentos │  │  Pedidos  │  │  Outros   │
         │ Service   │  │  Service  │  │ Services  │
         │  (8080)   │  │  (8081)   │  │           │
         └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
               │              │              │
               └──────────────┼──────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   Eureka Server     │
                    │   (porta 8761)      │
                    └─────────────────────┘
```

## Padrões de Roteamento

### Roteamento por Versão de API

```yaml
routes:
  - id: pagamentos-v1
    uri: lb://pagamentos-v1
    predicates:
      - Path=/api/v1/pagamentos/**
      
  - id: pagamentos-v2
    uri: lb://pagamentos-v2
    predicates:
      - Path=/api/v2/pagamentos/**
```

### Roteamento por Tenant

```yaml
routes:
  - id: tenant-specific
    uri: lb://pagamentos
    predicates:
      - Path=/api/v1/pagamentos/**
      - Header=X-Tenant-Id, .+
    filters:
      - AddRequestHeader=X-Forwarded-Tenant, ${header.X-Tenant-Id}
```

### Roteamento por Canary Deployment

```yaml
routes:
  - id: pagamentos-canary
    uri: lb://pagamentos-canary
    predicates:
      - Path=/api/v1/pagamentos/**
      - Weight=pagamentos-group, 10  # 10% do tráfego
      
  - id: pagamentos-stable
    uri: lb://pagamentos
    predicates:
      - Path=/api/v1/pagamentos/**
      - Weight=pagamentos-group, 90  # 90% do tráfego
```

## Performance e Otimização

### Cache de Respostas

```java
package br.com.bytecooks.gateway.filter;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class LocalResponseCacheGatewayFilterFactory 
        extends AbstractGatewayFilterFactory<LocalResponseCacheGatewayFilterFactory.Config> {
    
    private final ResponseCacheService cacheService;
    
    public LocalResponseCacheGatewayFilterFactory(ResponseCacheService cacheService) {
        super(Config.class);
        this.cacheService = cacheService;
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String cacheKey = generateCacheKey(exchange);
            
            return cacheService.get(cacheKey)
                .switchIfEmpty(
                    chain.filter(exchange)
                        .then(Mono.defer(() -> 
                            cacheService.put(cacheKey, exchange.getResponse())
                        ))
                )
                .then();
        };
    }
    
    private String generateCacheKey(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value() + 
               exchange.getRequest().getQueryParams().toString();
    }
    
    public static class Config {
        private int ttlSeconds = 300;
        
        // getters e setters
    }
}
```

### Timeout Configuration

```yaml
spring:
  cloud:
    gateway:
      httpclient:
        connect-timeout: 5000
        response-timeout: 10s
      routes:
        - id: pagamentos-with-timeout
          uri: lb://pagamentos
          predicates:
            - Path=/api/v1/pagamentos/**
          metadata:
            response-timeout: 5000
            connect-timeout: 2000
```

### Connection Pool

```yaml
spring:
  cloud:
    gateway:
      httpclient:
        pool:
          type: ELASTIC
          max-connections: 100
          max-idle-time: 30s
          max-life-time: 60s
```

## Troubleshooting

### Gateway não encontra serviços

**Problema**: Gateway retorna 503 Service Unavailable

**Soluções**:
1. Verifique se o Eureka Server está rodando
2. Confirme que os microsserviços estão registrados no Eureka
3. Verifique os logs do Gateway para erros de comunicação
4. Teste conectividade: `curl http://localhost:8761/eureka/apps`

### Rotas não funcionam

**Problema**: 404 Not Found para rotas configuradas

**Checklist**:
- Verifique o `spring.application.name` do serviço de destino
- Confirme que os predicates estão corretos
- Use `/actuator/gateway/routes` para ver rotas ativas
- Verifique se `enabled: true` em `discovery.locator`

### Circuit Breaker não abre

**Problema**: Requisições continuam falhando sem fallback

**Verificações**:
- Confirme que `resilience4j` está no classpath
- Verifique configuração de `minimum-number-of-calls`
- Monitore métricas: `/actuator/circuitbreakers`
- Aumente logging: `logging.level.io.github.resilience4j=DEBUG`

### Performance degradada

**Sintomas**: Gateway responde lentamente

**Otimizações**:
1. Aumente connection pool
2. Configure timeouts adequados
3. Implemente cache para endpoints frequentes
4. Use compressão de resposta
5. Monitore thread pool do WebFlux

## Boas Práticas

### Arquitetura

- **Stateless**: Gateway não deve manter estado de sessão
- **Idempotência**: Garanta que operações podem ser repetidas com segurança
- **Timeouts**: Configure timeouts agressivos para evitar cascata de falhas
- **Fallbacks**: Sempre forneça respostas alternativas quando serviços falharem
- **Versionamento**: Use versionamento de API desde o início

### Segurança

- **HTTPS Only**: Force HTTPS em produção
- **Rate Limiting**: Proteja contra abuso e DDoS
- **Autenticação**: Valide tokens no Gateway, não em cada serviço
- **Headers Sensíveis**: Remova headers internos antes de responder
- **CORS**: Configure CORS restritivamente

### Performance

- **Cache**: Cache respostas quando apropriado
- **Compressão**: Habilite compressão gzip/brotli
- **Connection Reuse**: Use HTTP/2 e keep-alive
- **Circuit Breaker**: Falhe rápido quando serviços estão instáveis
- **Monitoramento**: Monitore latência P50, P95, P99

### Observabilidade

- **Logs Estruturados**: Use JSON para logs
- **Correlation ID**: Propague ID único por toda a requisição
- **Métricas**: Colete métricas de negócio e técnicas
- **Distributed Tracing**: Implemente Sleuth/Zipkin
- **Alertas**: Configure alertas para métricas críticas

## Evolução do Gateway

### Próximas Implementações

1. **Authentication Service Integration**
    - Integração com Keycloak/Auth0
    - Validação de JWT
    - Refresh token handling

2. **Advanced Rate Limiting**
    - Rate limiting por usuário
    - Rate limiting por plano (free/premium)
    - Quotas mensais

3. **GraphQL Federation**
    - Gateway para múltiplas APIs GraphQL
    - Schema stitching

4. **Service Mesh Integration**
    - Integração com Istio
    - mTLS entre serviços

5. **API Documentation**
    - Agregação de documentação Swagger
    - Portal de desenvolvedores

## Recursos Adicionais

- [Spring Cloud Gateway Documentation](https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/)
- [Reactive Programming with Spring](https://spring.io/reactive)
- [Resilience4j Documentation](https://resilience4j.readme.io/)
- [API Gateway Pattern](https://microservices.io/patterns/apigateway.html)
- [Spring Cloud LoadBalancer](https://spring.io/guides/gs/spring-cloud-loadbalancer/)

## Padrões Relacionados

- **Backend for Frontend (BFF)**: Gateway específico por tipo de cliente
- **API Composition**: Agregação de múltiplas APIs
- **Strangler Fig**: Migração gradual de monolito para microsserviços
- **Sidecar**: Funcionalidades auxiliares ao lado do serviço principal

## Autores

- **Bytecooks Team**

## Licença

MIT License

---

**Status do Projeto**: Operacional ✅