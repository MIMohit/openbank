package bench;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerTypePredicate;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class App {
    public static void main(String[] args) {
        // OVERRIDE=on|off -> Spring Boot's documented switch for HiddenHttpMethodFilter,
        // spring.mvc.hiddenmethod.filter.enabled (Boot 3.5 evaluates it with
        // @ConditionalOnBooleanProperty, which only accepts true/false, so map on/off here).
        System.setProperty("spring.mvc.hiddenmethod.filter.enabled",
                String.valueOf("on".equals(System.getenv("OVERRIDE"))));
        // ROUTES=v2 (default off) enables RoutesV2Controller (W15 ext-routes). Off => :latest behaviour.
        String routes = System.getenv("ROUTES");
        System.setProperty("bench.routes", routes == null || routes.isEmpty() ? "off" : routes);
        SpringApplication.run(App.class, args);
    }
}

/**
 * /api/v2 is mounted as a path prefix applied to every controller annotated with
 * {@link V2Api}: Spring MVC's PathMatchConfigurer#addPathPrefix, the framework's
 * mechanism for mounting a group of handlers under a common prefix.
 */
@Configuration
class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.addPathPrefix("/api/v2", HandlerTypePredicate.forAnnotation(V2Api.class));
    }
}
