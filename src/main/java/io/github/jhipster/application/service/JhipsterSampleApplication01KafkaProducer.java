package io.github.jhipster.application.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
public class JhipsterSampleApplication01KafkaProducer {

    private static final Logger log = LoggerFactory.getLogger(JhipsterSampleApplication01KafkaProducer.class);
    private static final String TOPIC = "topic_jhipstersampleapplication01";

    private KafkaTemplate<String, String> kafkaTemplate;

    public JhipsterSampleApplication01KafkaProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void sendMessage(String message) {
        log.info("Producing message to {} : {}", TOPIC, message);
        this.kafkaTemplate.send(TOPIC, message);
    }
}
