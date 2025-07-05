import { PrismaClient, Status } from "@prisma/client"
import { Router } from "express"
import { z } from "zod"
import nodemailer from "nodemailer"

const prisma = new PrismaClient()
const router = Router()

// Validação de criação de pedido
const pedidoSchema = z.object({
  quantidade: z.number().min(1),
  status: z.nativeEnum(Status),
  mercadoria_id: z.number(),
  usuario_id: z.string(),
})

// GET /pedido/ — listar todos os pedidos
router.get("/", async (req, res) => {
  try {
    const pedidos = await prisma.pedido.findMany({
      include: { usuario: true, mercadoria: true },
      orderBy: { id: 'desc' }
    })
    res.status(200).json(pedidos)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

// GET /pedido/ — Listar todos os pedidos ou filtrar por status
router.get("/", async (req, res) => {
  // 1. Validação do Parâmetro de Status (se existir)
  const statusSchema = z.nativeEnum(Status).optional();
  const result = statusSchema.safeParse(req.query.status);

  // Se a validação falhar, retorna um erro claro.
  if (!result.success) {
    return res.status(400).json({ 
        erro: "Status inválido.",
        details: "Os valores permitidos são: PENDENTE, EM_PREPARACAO, A_CAMINHO, ENTREGUE, CANCELADO"
    });
  }
  
  const status = result.data;

  try {
    // 2. Criação da Cláusula 'where' para a consulta
    // A cláusula 'where' será usada no findMany do Prisma.
    const whereClause = status 
      ? { status: status } // Se um status válido foi fornecido, filtra por ele.
      : {};               // Se não, o objeto fica vazio e busca todos os pedidos.

    // 3. Execução da Consulta no Banco de Dados
    const pedidos = await prisma.pedido.findMany({
      where: whereClause, // Aplica o filtro aqui
      include: { usuario: true, mercadoria: true },
      orderBy: { id: 'desc' }
    });
    
    // Se nenhum pedido for encontrado, retorna um array vazio.
    res.status(200).json(pedidos);

  } catch (error) {
    res.status(500).json({ erro: "Ocorreu um erro ao buscar os pedidos.", details: error });
  }
});

// POST /pedido/ — criar novo pedido
router.post("/", async (req, res) => {
  const valida = pedidoSchema.safeParse(req.body)
  if (!valida.success) {
    res.status(400).json({ erro: valida.error })
    return
  }
  try {
    const pedido = await prisma.pedido.create({
      data: valida.data
    })
    res.status(201).json(pedido)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

// Função de envio de e-mail para atualização de status do pedido
async function enviaEmailPedido(
  nome: string,
  email: string,
  mercadoria: string,
  status: string
) {
  const transporter = nodemailer.createTransport({
    // host: "sandbox.smtp.mailtrap.io",
    // port: 587,
    // secure: false,
    // auth: {
    //   user: "968f0dd8cc78d9",
    //   pass: "89ed8bfbf9b7f9"
    // }
    host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
  })

  const info = await transporter.sendMail({
    // from: 'no-reply@seusistema.com',
    from: process.env.SMTP_FROM,
    to: email,
    subject: `Atualização do seu pedido: ${mercadoria}`,
    text: `Olá ${nome},\n\nSeu pedido da mercadoria "${mercadoria}" agora está com status: ${status}.`,
    html: `
      <h3>Olá, ${nome}</h3>
      <p>Sua mercadoria: <strong>${mercadoria}</strong></p>
      <p>Status do pedido: <strong>${status}</strong></p>
      <p>Obrigado por comprar conosco!</p>
    `
  })

  console.log("E-mail enviado: %s", info.messageId)
}

// PATCH /pedido/:id — atualizar status e/ou motoboy, e enviar e-mail
router.patch("/:id", async (req, res) => {
  const { id } = req.params
  const { status } = req.body

  if (!status) {
    res.status(400).json({ erro: "Informe o novo status do pedido" })
    return
  }

  try {
    // Atualiza o pedido
    const pedido = await prisma.pedido.update({
      where: { id: Number(id) },
      data: {
        status
      }
    })
    res.status(200).json(pedido)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})



// PATCH /pedido/:id — atualizar status e/ou motoboy, e enviar e-mail
router.patch("/:id", async (req, res) => {
  const { id } = req.params
  const { status, motoboy_id } = req.body

  if (!status) {
    res.status(400).json({ erro: "Informe o novo status do pedido" })
    return
  }

  try {
    // Atualiza o pedido
    const pedido = await prisma.pedido.update({
      where: { id: Number(id) },
      data: {
        status
      }
    })

    // Busca dados para envio de e-mail
    const dados = await prisma.pedido.findUnique({
      where: { id: Number(id) },
      include: {
        usuario: true,
        mercadoria: true
      }
    })

    if (dados) {
      await enviaEmailPedido(
        dados.usuario.nome as string,
        dados.usuario.email as string,
        dados.mercadoria.nome as string,
        status
      )
    }

    res.status(200).json(pedido)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

// GET /pedido/:usuarioId — pedidos de um usuario
router.get("/:usuario_id", async (req, res) => {
  const { usuario_id } = req.params
  try {
    const pedidos = await prisma.pedido.findMany({
      where: { usuario_id: String(usuario_id) },
      include: { mercadoria: true }
    })
    res.status(200).json(pedidos)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

// DELETE /pedido/:id — remover pedido
router.delete("/:id", async (req, res) => {
  const { id } = req.params
  try {
    const pedido = await prisma.pedido.delete({
      where: { id: Number(id) }
    })
    res.status(200).json(pedido)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

export default router
