package org.example;

import com.rabbitmq.client.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.security.Security;
import java.util.Base64;

        public class VPNServer {
            private static final String RABBITMQ_HOST = "localhost";
            private static final String EXCHANGE_NAME = "vpn_exchange";
            private static final int TUN_MTU = 1500;
            private static final byte[] ENCRYPTION_KEY = "YourSecretKey123".getBytes();

            private Connection connection;
            private Channel channel;
            private String nodeId;

            public VPNServer(String nodeId) {
                this.nodeId = nodeId;
                Security.addProvider(new BouncyCastleProvider());
            }

            public void start() throws Exception {
                // Set up RabbitMQ connection
                ConnectionFactory factory = new ConnectionFactory();
                factory.setHost(RABBITMQ_HOST);
                connection = factory.newConnection();
                channel = connection.createChannel();

                // Declare exchange
                channel.exchangeDeclare(EXCHANGE_NAME, "fanout");
                String queueName = channel.queueDeclare().getQueue();
                channel.queueBind(queueName, EXCHANGE_NAME, "");

                // Create TUN interface
                setupTunInterface();

                // Start packet processor
                startPacketProcessor(queueName);
            }

            private void setupTunInterface() throws Exception {
                // This would need to be implemented using JNI or native calls
                // to create a TUN interface on the specific OS
                System.out.println("Setting up TUN interface...");
            }

            private void startPacketProcessor(String queueName) throws Exception {
                // Handle incoming packets from RabbitMQ
                DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                    byte[] encryptedData = delivery.getBody();
                    try {
                        // Decrypt the packet
                        byte[] decryptedData = decrypt(encryptedData);
                        // Write to TUN interface
                        writeTunInterface(decryptedData);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                };

                channel.basicConsume(queueName, true, deliverCallback, consumerTag -> {});

                // Start reading from TUN interface
                Thread tunReader = new Thread(() -> {
                    try {
                        byte[] buffer = new byte[TUN_MTU];
                        while (true) {
                            // Read from TUN interface
                            int bytesRead = readTunInterface(buffer);
                            if (bytesRead > 0) {
                                // Encrypt the packet
                                byte[] encryptedData = encrypt(buffer, bytesRead);
                                // Publish to RabbitMQ
                                channel.basicPublish(EXCHANGE_NAME, "", null, encryptedData);
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                tunReader.start();
            }

            private byte[] encrypt(byte[] data, int length) throws Exception {
                byte[] input = new byte[length];
                System.arraycopy(data, 0, input, 0, length);

                SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
                byte[] iv = new byte[16];
                // In production, use a proper IV generation method
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

                return cipher.doFinal(input);
            }

            private byte[] decrypt(byte[] encryptedData) throws Exception {
                SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
                byte[] iv = new byte[16];
                // In production, use the same IV as encryption
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

                return cipher.doFinal(encryptedData);
            }

            private int readTunInterface(byte[] buffer) {
                // This would need to be implemented using JNI or native calls
                // to read from the TUN interface
                return 0;
            }

            private void writeTunInterface(byte[] data) {
                // This would need to be implemented using JNI or native calls
                // to write to the TUN interface
            }

            public static void main(String[] args) {
                try {
                    if (args.length != 1) {
                        System.out.println("Usage: java VPNServer <node-id>");
                        return;
                    }

                    VPNServer server = new VPNServer(args[0]);
                    server.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }



    }
}