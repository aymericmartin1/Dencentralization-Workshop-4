import axios from "axios";
import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, BASE_USER_PORT, REGISTRY_PORT } from "../config";
import {
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt,
} from "../crypto";

interface Node {
  nodeId: number;
  pubKey: string;
}

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body as SendMessageBody;
    console.log(`User ${userId} received message: ${message}`);
    lastReceivedMessage = message;
    res.send("success");
  });

_user.post("/sendMessage", async (req, res) => {
  const { message, destinationUserId } = req.body as SendMessageBody;
  try {
    lastSentMessage = message;

    console.log(`User ${userId} sending message ('${message}') to user ${destinationUserId}`);

    const { data } = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    console.log(data);
    const nodes = data.nodes;

    const circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.includes(randomNode)) {
        circuit.push(randomNode);
      }
    }
    console.log(circuit); 

    lastCircuit = circuit.map(node => node.nodeId);

    let encryptedMessage = message;
    let destination = (BASE_USER_PORT + destinationUserId).toString().padStart(10, '0');

    for (let i = 0; i < circuit.length; i++) {
      const symmetricKey = await createRandomSymmetricKey();
      const strSymKey = await exportSymKey(symmetricKey);
      const encryptedSymKey = await rsaEncrypt(strSymKey, circuit[i].pubKey);
      const encryptedMessageLayer = await symEncrypt(symmetricKey, destination + encryptedMessage);
      
      destination = (BASE_ONION_ROUTER_PORT + circuit[i].nodeId).toString().padStart(10, '0');
      encryptedMessage = encryptedSymKey + encryptedMessageLayer;
      console.log(symmetricKey, strSymKey, encryptedSymKey, encryptedMessage);
    }

    console.log(`User ${userId} using circuit ${circuit.map(node => node.nodeId).join(' -> ')}`);
    console.log(`Sending to node ${circuit[0].nodeId}, through url : http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`);
    circuit.reverse();
    lastCircuit = circuit.map(node => node.nodeId);

    await axios.post(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      message: encryptedMessage,
    });
    console.log(`Message sent to user ${destinationUserId}, returning 200 response`);
    return res.sendStatus(200);

  } catch (error) {
    console.error("Error sending message:", error);
    return res.status(500).json({ error: "Failed to send message" });
  }
});



  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
