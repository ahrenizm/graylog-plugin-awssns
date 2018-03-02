/**
 * Copyright 2013-2014 TORCH GmbH, 2015 Graylog, Inc.
 *
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.alarmcallbacks.awssns;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.MessageAttributeValue;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.AlarmCallback;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Math.min;

public class AWSSNSAlarmCallback implements AlarmCallback {
    private static final Logger LOG = LoggerFactory.getLogger(AWSSNSAlarmCallback.class);

    private static final String NAME = "AWS SNS Alarm Callback";
    private static final int MAX_MSG_LENGTH = 140;

    private static final String CK_ACCESS_KEY = "access_key";
    private static final String CK_SECRET_KEY = "secret_key";
    private static final String CK_REGION = "region";
    private static final String CK_PROXY_HOST = "proxy_host";
    private static final String CK_PROXY_PORT = "proxy_port";
    private static final String CK_FROM = "from";
    private static final String CK_TO = "to";
    private static final String[] MANDATORY_CONFIGURATION_KEYS = new String[]{
            CK_ACCESS_KEY, CK_SECRET_KEY, CK_REGION, CK_FROM, CK_TO
    };
    private static final List<String> SENSITIVE_CONFIGURATION_KEYS = ImmutableList.of(CK_SECRET_KEY);

    private Configuration configuration;

    @Override
    public void initialize(final Configuration config) throws AlarmCallbackConfigurationException {
        this.configuration = config;
    }

    @Override
    public void call(Stream stream, AlertCondition.CheckResult result) throws AlarmCallbackException {
        AWSCredentials awsCredentials = new BasicAWSCredentials(configuration.getString(CK_ACCESS_KEY), configuration.getString(CK_SECRET_KEY));
        ClientConfiguration clientConfiguration = new ClientConfiguration();
        if (!configuration.getString(CK_PROXY_HOST).isEmpty()) {
            clientConfiguration.setProxyHost(configuration.getString(CK_PROXY_HOST));
            clientConfiguration.setProxyPort(configuration.getInt(CK_PROXY_PORT));
        }
        final AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
            .withClientConfiguration(clientConfiguration)
            .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
            .withRegion(configuration.getString(CK_REGION)).build();
        call(stream, result, snsClient);
    }

    @Override
    public ConfigurationRequest getRequestedConfiguration() {
        final ConfigurationRequest cr = new ConfigurationRequest();

        cr.addField(new TextField(CK_ACCESS_KEY, "AWS Access Key", "", "Amazon access key",
                ConfigurationField.Optional.NOT_OPTIONAL));
        cr.addField(new TextField(CK_SECRET_KEY, "AWS Secret Key", "", "Amazon secret key",
                ConfigurationField.Optional.NOT_OPTIONAL, TextField.Attribute.IS_PASSWORD));
        cr.addField(new TextField(CK_REGION, "AWS Region", "ap-southeast-2", "AWS region",
                ConfigurationField.Optional.NOT_OPTIONAL));
        cr.addField(new TextField(CK_FROM, "Sender", "",
                "Contigous alphanumeric without whitespace",
                ConfigurationField.Optional.NOT_OPTIONAL));
        cr.addField(new TextField(CK_TO, "Recipient Topic or Phone Number", "",
                "Predefined SNS topic or a phone number, if starting with '+'",
                ConfigurationField.Optional.NOT_OPTIONAL));
        cr.addField(new TextField(CK_PROXY_HOST, "Proxy Host", "", "Optional proxy server host", ConfigurationField.Optional.OPTIONAL));
        cr.addField(new NumberField(CK_PROXY_PORT, "Proxy Port", 3128, "Optional proxy server port",ConfigurationField.Optional.OPTIONAL));
        
        return cr;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Maps.transformEntries(configuration.getSource(), new Maps.EntryTransformer<String, Object, Object>() {
            @Override
            public Object transformEntry(String key, Object value) {
                if (SENSITIVE_CONFIGURATION_KEYS.contains(key)) {
                    return "****";
                }
                return value;
            }
        });
    }

    @Override
    public void checkConfiguration() throws ConfigurationException {
        for (String key : MANDATORY_CONFIGURATION_KEYS) {
            if (!configuration.stringIsSet(key)) {
                throw new ConfigurationException(key + " is mandatory and must not be empty.");
            }
        }
    }


    @VisibleForTesting
    void call(final Stream stream, final AlertCondition.CheckResult result, final AmazonSNS snsClient) {
        send(snsClient, result);
    }

    public String getName() {
        return NAME;
    }

    private void send(final AmazonSNS client, final AlertCondition.CheckResult result) {

        PublishRequest publishRequest = new PublishRequest()
            .withMessage(buildMessage(result));

        if (configuration.getString(CK_TO).startsWith("+"))
            publishRequest.setPhoneNumber(configuration.getString(CK_TO));
        else
            publishRequest.setTopicArn(client.createTopic(configuration.getString(CK_TO)).getTopicArn());

        Map<String, MessageAttributeValue> messageAttributes = new HashMap<String, MessageAttributeValue>();
        messageAttributes.put("DisplayName", new MessageAttributeValue().withDataType("String").withStringValue(configuration.getString(CK_FROM)));
        publishRequest.setMessageAttributes(messageAttributes);

        PublishResult publishResult = client.publish(publishRequest);
        
        LOG.debug("Sent SMS with ID {} to {}", publishResult.getMessageId(), configuration.getString(CK_TO));
    }

    private String buildMessage(final AlertCondition.CheckResult result) {
        final String msg = result.getResultDescription();
        return msg.substring(0, min(msg.length(), MAX_MSG_LENGTH));
    }
}