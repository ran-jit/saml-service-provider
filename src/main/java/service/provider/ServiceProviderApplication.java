package service.provider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@SpringBootApplication
@ComponentScan(basePackages = "service.provider")
public class ServiceProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceProviderApplication.class);
    }

}
