package tracefusion.xmark;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
public class XMarkPropagationAutoConfiguration {
    private static final String X_MARK = "X-Mark";
    private static final String X_MARK_LOWER = "x-mark";

    @Bean
    public static BeanPostProcessor xMarkRestTemplatePostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
                return bean;
            }

            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
                if (bean instanceof RestTemplate) {
                    RestTemplate restTemplate = (RestTemplate) bean;
                    List<ClientHttpRequestInterceptor> interceptors =
                        new ArrayList<ClientHttpRequestInterceptor>(restTemplate.getInterceptors());
                    for (ClientHttpRequestInterceptor interceptor : interceptors) {
                        if (interceptor instanceof XMarkPropagationInterceptor) {
                            return bean;
                        }
                    }
                    interceptors.add(new XMarkPropagationInterceptor());
                    restTemplate.setInterceptors(interceptors);
                    System.err.println("[trace-fusion] enabled X-Mark propagation on RestTemplate bean: " + beanName);
                }
                return bean;
            }
        };
    }

    static class XMarkPropagationInterceptor implements ClientHttpRequestInterceptor {
        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
                throws IOException {
            String mark = currentXMark();
            if (mark != null && mark.length() > 0 && !request.getHeaders().containsKey(X_MARK)) {
                request.getHeaders().set(X_MARK, mark);
            }
            return execution.execute(request, body);
        }

        private String currentXMark() {
            RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
            if (!(attrs instanceof ServletRequestAttributes)) {
                return null;
            }
            HttpServletRequest currentRequest = ((ServletRequestAttributes) attrs).getRequest();
            String mark = currentRequest.getHeader(X_MARK);
            if (mark == null || mark.length() == 0) {
                mark = currentRequest.getHeader(X_MARK_LOWER);
            }
            return mark;
        }
    }
}
