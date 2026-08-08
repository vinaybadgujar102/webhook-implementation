import Express from "express";
import crypto from "crypto";
import z from "zod";
// {
//   "id": "evt_12345",
//   "type": "payment.succeeded",
//   "created_at": 1723100000,
//   "data": {
//     "payment_id": "pay_123",
//     "amount": 4999,
//     "currency": "INR"
//   }
// }

declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
    }
  }
}

enum PaymentStatus {
  SUCCEEDED = "payment.succeeded",
}

enum Currency {
  INR = "INR",
}

const paymentEventPayloadSchema = z.object({
  id: z.string(),
  type: z.enum(PaymentStatus),
  created_at: z.number(),
  data: z.object({
    payment_id: z.string(),
    amount: z.number(),
    currency: z.enum(Currency),
  }),
});

const app = Express();

app.use(
  Express.json({
    verify(req, res, buf) {
      req.rawBody = buf;
    },
  }),
);

app.post("/webhook/payment", (req, res) => {
  try {
    const signature = req.header("X-Webhook-Signature");
    if (!signature || !req.rawBody) {
      return res.sendStatus(201);
    }

    const expected = crypto
      .createHmac("sha256", "SECRET")
      .update(req.rawBody)
      .digest("hex");

    if (expected !== signature) {
      return res.sendStatus(401);
    }

    const paylaod = paymentEventPayloadSchema.parse(req.body);

    return res.status(200).json({
      success: true,
      message: `${paylaod.type} event successfully processed.`,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.log(error.issues);
      return res.status(400).json({
        success: false,
        message: "Bad payload",
      });
    }
  }
  console.log(req);
});

app.listen(3000, () => {
  console.log("server running on port 3000");
});

