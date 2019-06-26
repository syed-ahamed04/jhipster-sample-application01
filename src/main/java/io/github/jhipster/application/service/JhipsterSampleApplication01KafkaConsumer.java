package io.github.jhipster.application.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class JhipsterSampleApplication01KafkaConsumer {

    private final Logger log = LoggerFactory.getLogger(JhipsterSampleApplication01KafkaConsumer.class);
    private static final String TOPIC = "topic_jhipstersampleapplication01";

    @KafkaListener(topics = "topic_jhipstersampleapplication01", groupId = "group_id")
    public void consume(String message) throws IOException {
        log.info("Consumed message in {} : {}", TOPIC, message);
    }
}
