import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import axios from "axios";
import {
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt,
} from "../crypto";

type Node = {
  nodeId: number;
  pubKey: string;
};

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

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body as SendMessageBody;
    lastReceivedMessage = message;
    res.sendStatus(200);
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;

    const { data } = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    const nodes = data.nodes;

    const circuit: Node[] = [];
    while (circuit.length < 3) {
      const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
      if (!circuit.includes(randomNode)) {
        circuit.push(randomNode);
      }
    }

    let encryptedMessage = message;
    for (let i = 0; i < circuit.length; i++) {
      const symmetricKey = await createRandomSymmetricKey();
      const strSymKey = await exportSymKey(symmetricKey);
      const encryptedSymKey = await rsaEncrypt(strSymKey, circuit[i].pubKey);
      encryptedMessage = await symEncrypt(symmetricKey, encryptedMessage);
      encryptedMessage = encryptedSymKey + encryptedMessage;
    }

    await axios.post(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      message: encryptedMessage,
    });

    res.sendStatus(200);
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
