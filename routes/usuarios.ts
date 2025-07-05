

import { Router, Request, Response } from "express";
import { PrismaClient } from '@prisma/client'
import { z } from 'zod'

import bcrypt, { compareSync } from "bcrypt";
import jwt from 'jsonwebtoken';
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const prisma = new PrismaClient()

const router = Router()

const usuarioSchema = z.object({
  nome: z.string().min(2,
    { message: "Nome deve possuir, no mínimo, 2 caracteres" }),

  email: z.string().email({
      message: "E-mail inválido"
    }),
  
  senha: z.string()
      .min(8, { message: "A senha deve ter no mínimo 8 caracteres" })
      .regex(/[A-Z]/, { message: "A senha deve conter pelo menos uma letra maiúscula" })
      .regex(/[^A-Za-z0-9]/, { message: "A senha deve conter pelo menos um caractere especial" }),
  
  telefone: z.string()
      .regex(/^\d{10,13}$/, {
        message: "Telefone deve conter apenas números e ter entre 10 e 11 dígitos"
      }),
  
  endereco: z.string().min(2, {
      message: "Endereço deve possuir, no mínimo, 2 caracteres"
    }),
  })

// router.get("/", async (req, res) => {
//   try {
//     const usuario = await prisma.usuario.findMany({
    
//     })
//     res.status(200).json(usuario)
//   } catch (error) {
//     res.status(500).json({ erro: error })
//   }
// })
// ROTA PRINCIPAL GET /usuarios
router.get("/", async (req: Request, res: Response) => {
  const { telefone } = req.query;

  try {
    // SE um telefone foi passado como query param
    if (telefone) {
      const telefoneLimpo = String(telefone).trim();
      const usuario = await prisma.usuario.findFirst({
        where: { telefone: telefoneLimpo }
      });
      // Retorna o usuário encontrado (ou null se não encontrar)
      return res.status(200).json(usuario);
    }

    // SE NENHUM telefone foi passado, lista todos os usuários
    const usuarios = await prisma.usuario.findMany({
      orderBy: { nome: 'asc' }
    });
    return res.status(200).json(usuarios);

  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    return res.status(500).json({ erro: "Erro interno no servidor" });
  }
});

router.post("/", async (req, res) => {
  const valida = usuarioSchema.safeParse(req.body)
  if (!valida.success) {
    return res.status(400).json({ erro: valida.error.errors });
  }

  const { nome, email, senha, telefone, endereco } = valida.data;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(senha, salt);

    const usuario = await prisma.usuario.create({
      data: {
        nome,
        email,
        senha: hashedPassword,
        telefone,
        endereco,
      },
    });
    res.status(201).json({ message: "Usuário cadastrado com sucesso", usuario });
  } catch (error: any) {
    if (error.code === 'P2002') { // Unique constraint violation
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }
    console.error(error);
    res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
  }
});

// Rota de Login
router.post("/login", async (req: Request, res: Response) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ error: "Email e senha são obrigatórios" });
  }

  try {
    const usuario = await prisma.usuario.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Gerar token JWT (opcional, mas recomendado)
    const token = jwt.sign(
      { 
        userId: usuario.id,
        email: usuario.email,
        // userNivel: usuario.nivel,
      },
      process.env.JWT_SECRET || 'sua-chave-secreta', // Use uma chave segura no ambiente de produção
      { expiresIn: '1h' } // Define a expiração do token
    );

    res.json({ message: "Login bem-sucedido", token, usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email} });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao realizar login" });
  }
});

router.delete("/:id", async (req, res) => {
  const { id } = req.params

  try {
    const usuario = await prisma.usuario.delete({
      where: { id }
    })
    res.status(200).json(usuario)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

router.put("/:id", async (req, res) => {
  const { id } = req.params

  const valida = usuarioSchema.safeParse(req.body)
  if (!valida.success) {
    res.status(400).json({ erro: valida.error })
    return
  }

  const { nome, email, senha, telefone, endereco } = valida.data

  try {
    const usuario = await prisma.usuario.update({
      where: { id },
      data: {
        nome, email, senha, telefone, endereco
      }
    })
    res.status(200).json(usuario)
  } catch (error) {
    res.status(400).json({ error })
  }
})

router.get("/pesquisa/:termo", async (req, res) => {
  const { termo } = req.params

  try {
    const usuarios = await prisma.usuario.findMany({
      where: {
        OR: [
          {
              nome: {
                contains: termo,
                mode: "insensitive"
              }
          },
          // {
          //   endereco: {
          //     contains: termo,
          //     mode: "insensitive"
          //   }
          // },
          {
            telefone: {
              contains: termo,
              mode: "insensitive"
            }
          }
        ]
      }
    })

    res.status(200).json(usuarios)
  } catch (error) {
    console.error(error)
    res.status(500).json({ erro: error })
  }
})

// Rota de Consulta de consumidor pelo Id, retorna um OBJETO, não um ARRAY
// router.get("/:id", async (req, res) => {
//   const { id } = req.params

//   try {
//     const usuario = await prisma.usuario.findUnique({
//       where: { id },
//     })
//     res.status(200).json(usuario)
//   } catch (error) {
//     res.status(400).json(error)
//   }
// })
router.get("/", async (req: Request, res: Response) => {
  const { telefone } = req.query;

  try {
    // SE um telefone foi passado como query param
    if (telefone) {
      const telefoneLimpo = String(telefone).trim();
      const usuario = await prisma.usuario.findFirst({
        where: { telefone: telefoneLimpo }
      });
      // Retorna o usuário encontrado (ou null se não encontrar)
      return res.status(200).json(usuario);
    }

    // SE NENHUM telefone foi passado, lista todos os usuários
    const usuarios = await prisma.usuario.findMany({
      orderBy: { nome: 'asc' }
    });
    return res.status(200).json(usuarios);

  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    return res.status(500).json({ erro: "Erro interno no servidor" });
  }
});

// GET /usuarios/:id — Rota para buscar um usuário pelo seu ID (única)
// Esta rota não conflita mais com a busca por telefone.
// GET /usuarios/:id — Rota para buscar um usuário pelo seu ID (única)
router.get("/:id", async (req: Request, res: Response) => {
  const { id } = req.params; // <-- Aqui usamos req.params.id
  try {
    const usuario = await prisma.usuario.findUnique({
      where: { id },
    });
    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado" });
    }
    res.status(200).json(usuario);
  } catch (error) {
    res.status(500).json({ erro: "Erro ao buscar usuário" });
  }
});

// GET /usuarios/:id — Rota para buscar um usuário pelo seu ID (única)
// Esta rota não conflita mais com a busca por telefone.
// router.get("/:id", async (req: Request, res: Response) => {
//   const { id } = req.params;
//   try {
//     const usuario = await prisma.usuario.findUnique({
//       where: { id },
//     });
//     if (!usuario) {
//       return res.status(404).json({ erro: "Usuário não encontrado" });
//     }
//     res.status(200).json(usuario);
//   } catch (error) {
//     res.status(500).json({ erro: "Erro ao buscar usuário" });
//   }
// });
// ROTA PRINCIPAL GET /usuarios
// Se houver "?telefone=...", busca por telefone.
// Se não, lista todos os usuários.


// 1) Solicitar código de recuperação
router.post("/solicitar-recuperacao", async (req: Request, res: Response) => {
    try {
      const { email } = req.body;
      if (!email)
        return res.status(400).json({ error: "Email é obrigatório" });

      const usuario = await prisma.usuario.findUnique({
        where: { email },
      });
      if (!usuario)
        return res
          .status(404)
          .json({ error: "Usuario não encontrado" });

      // Gera um código numérico de 6 dígitos
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      await prisma.usuario.update({
        where: { email },
        data: { codigoRecuperacao: code },
      });
      // teste
      // console.log(usuario.codigoRecuperacao)
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: email,
        subject: "Código de recuperação de senha",
        text: `Use este código para recuperar sua senha: ${code}`,
      });

      return res.json({
        message: "Código de recuperação enviado para seu email",
      });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Erro interno" });
    }
  }
);

// 2) Alterar senha usando código de recuperação
router.patch(
  "/alterar-senha",
  async (req: Request, res: Response) => {
    try {
      const {
        email,
        codigoRecuperacao,
        novaSenha: novaSenha, // variavel
        confirmarSenha: confirmarSenha, // variavel
      } = req.body;
      if (
        !email ||
        !codigoRecuperacao ||
        !novaSenha ||
        !confirmarSenha
      ) {
        return res
          .status(400)
          .json({ error: "Todos os campos são obrigatórios" });
      }
      if (novaSenha !== confirmarSenha) {
        return res
          .status(400)
          .json({ error: "As senhas não coincidem" });
      }

      const usuario = await prisma.usuario.findUnique({
        where: { email },
      });
      if (
        !usuario ||
        usuario.codigoRecuperacao !== codigoRecuperacao
      ) {
        return res
          .status(400)
          .json({ error: "Código de recuperação inválido" });
      }

      const hash = await bcrypt.hash(novaSenha, 10);
      await prisma.usuario.update({
        where: { email },
        data: { senha: hash, codigoRecuperacao: null },
      });


      return res.json({ message: "Senha alterada com sucesso" });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Erro interno" });
    }
  }
);

// // GET /usuarios/:telefone — busca um usuário único pelo telefone
// router.get("/:telefone", async (req, res) => {
//   // Pega o 'telefone' dos parâmetros do caminho (path parameters)
//   const { telefone } = req.params

//   // --- LOG DE DEPURAÇÃO 1 ---
//   console.log("--- NOVA REQUISIÇÃO RECEBIDA ---");
//   console.log("Parâmetro 'telefone' recebido da URL:", telefone);

//   // Se nenhum telefone for fornecido na URL, retorna um erro.
//   // (Em uma rota com path param, isso é quase impossível, mas é uma boa prática)
//   if (!telefone) {
//     res.status(400).json({ erro: "Parâmetro 'telefone' é obrigatório" })
//     return
//   }

//   // --- LINHA CRUCIAL DA CORREÇÃO ---
//   // A função .trim() remove todos os espaços em branco do início e do fim.
//   const telefoneLimpo = telefone.trim()

//   // --- LOG DE DEPURAÇÃO 2 ---
//   // Log com aspas para vermos se há espaços invisíveis
//   console.log("Telefone após .trim():", `"${telefoneLimpo}"`);

//   try {

//     // --- LOG DE DEPURAÇÃO 3 ---
//     console.log("Executando busca no Prisma com o 'where':", { where: { telefone: telefoneLimpo } });

//     // Busca na tabela por um usuário ÚNICO onde o telefone corresponda.
//     // Usamos findUnique porque o resultado 'null' indica que esta é a função usada.
//     const usuario = await prisma.usuario.findFirst({
//       where: {
//         // Agora usamos a variável "limpa" para a busca
//         telefone: telefoneLimpo
//       }
//     })

//     // --- LOG DE DEPURAÇÃO 4 ---
//     console.log("Resultado da busca no Prisma:", usuario); // Isso mostrará 'null' ou o objeto do usuário
//     console.log("--- FIM DA REQUISIÇÃO ---");

//     // Retorna o usuário encontrado ou null se não encontrar.
//     res.status(200).json(usuario)

//   } catch (error) {
//      console.error("ERRO NA EXECUÇÃO DO PRISMA:", error);
//     // Em caso de erro no banco de dados, retorna um erro genérico.
//     res.status(400).json({ erro: error })
//   }
// })

export default router
