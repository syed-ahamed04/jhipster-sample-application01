package io.github.jhipster.application.web.rest;

import io.github.jhipster.application.service.JhipsterSampleApplication01KafkaProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/jhipster-sample-application-01-kafka")
public class JhipsterSampleApplication01KafkaResource {

    private final Logger log = LoggerFactory.getLogger(JhipsterSampleApplication01KafkaResource.class);

    private JhipsterSampleApplication01KafkaProducer kafkaProducer;

    public JhipsterSampleApplication01KafkaResource(JhipsterSampleApplication01KafkaProducer kafkaProducer) {
        this.kafkaProducer = kafkaProducer;
    }

    @PostMapping(value = "/publish")
    public void sendMessageToKafkaTopic(@RequestParam("message") String message) {
        log.debug("REST request to send to Kafka topic the message : {}", message);
        this.kafkaProducer.sendMessage(message);
    }
}
