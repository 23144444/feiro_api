import { PrismaClient } from '@prisma/client'
import { Router } from 'express'
import { z } from 'zod'
import bcrypt from 'bcrypt'
import { verificaToken } from '../middlewares/verificaToken';
import { verificaNivel } from '../middlewares/verificaNivel';

const prisma = new PrismaClient()
// const prisma = new PrismaClient({
//   log: [
//     {
//       emit: 'event',
//       level: 'query',
//     },
//     {
//       emit: 'stdout',
//       level: 'error',
//     },
//     {
//       emit: 'stdout',
//       level: 'info',
//     },
//     {
//       emit: 'stdout',
//       level: 'warn',
//     },
//   ],
// })

// prisma.$on('query', (e) => {
//   console.log('Query: ' + e.query)
//   console.log('Params: ' + e.params)
//   console.log('Duration: ' + e.duration + 'ms')
// })

const router = Router()

const feiranteSchema = z.object({
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
      .regex(/^\d{10,11}$/, {
        message: "Telefone deve conter apenas números e ter entre 10 e 11 dígitos"
      }),
    // usuario_id: z.string(),
  })

router.get("/", async (req, res) => {
  try {
    const feirantes = await prisma.feirante.findMany({
    
    })
    res.status(200).json(feirantes)
  } catch (error) {
    res.status(500).json({ erro: error })
  }
})

router.post("/",  async (req, res) => {
  // verificaNivel(3),
  //verificaToken,

  const valida = feiranteSchema.safeParse(req.body)
  if (!valida.success) {
    res.status(400).json({ erro: valida.error })
    return
  }

  const { nome, email, senha, telefone } = valida.data

  try {
    const salt = await bcrypt.genSalt(10);
    const senhaHash = await bcrypt.hash(senha, salt);
    const feirante = await prisma.feirante.create({
      data: {
        nome,
        email,
        senha: senhaHash,
        telefone
      }
    })
    const { senha: _, ...feiranteSemSenha } = feirante;
    res.status(201).json(feiranteSemSenha)
  } catch (error) {
    res.status(400).json({ error })
  }
})

router.delete("/:id", verificaToken, async (req, res) => {
  // verificaToken,
  // verificaNivel(3),
  const { id } = req.params

  try {
    const feirante = await prisma.feirante.delete({
      where: { id: Number(id) }
    })
    res.status(200).json(feirante)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

// router.put("/:id", async (req, res) => {
//   const { id } = req.params

//   const valida = feiranteSchema.safeParse(req.body)
//   if (!valida.success) {
//     res.status(400).json({ erro: valida.error })
//     return
//   }

//   const { nome, email, senha, telefone, localizacao } = valida.data

//   try {
//     const feirante = await prisma.feirante.update({
//       where: { id: Number(id) },
//       data: {
//         nome, email, senha, telefone, localizacao
//       }
//     })
//     res.status(200).json(feirante)
//   } catch (error) {
//     res.status(400).json({ error })
//   }
// })

router.put("/:id", async (req, res) => {
  const { id } = req.params
  const valida = feiranteSchema.safeParse(req.body)
  if (!valida.success) {
    return res.status(400).json({ erro: valida.error })
  }
  const { nome, email, senha, telefone } = valida.data

  try {
    // Busca feirante + localização atual para obter o ID
    const feiranteAtual = await prisma.feirante.findUnique({
      where: { id: Number(id) },
    })
    if (!feiranteAtual) {
      return res.status(404).json({ erro: "Feirante não encontrado" })
    }

    // Nested update: data fica DENTRO de update
    const updatedFeirante = await prisma.feirante.update({
      where: { id: Number(id) },
      data: {
        nome,
        email,
        senha,
        telefone
      }
    })

      return res.status(200).json(updatedFeirante)
  } catch (error) {
    return res.status(500).json({ erro: error })
  }
})



router.get("/pesquisa/:termo", async (req, res) => {
  const { termo } = req.params

  try {
    const feirantes = await prisma.feirante.findMany({
      where: {
        OR: [
          {
            nome: {
              contains: termo,
              mode: "insensitive"
            }
          },
        //   {
        //     localizacao: {
        //       contains: termo,
        //       mode: "insensitive"
        //     }
        //   }
        ]
      }
    })
    res.status(200).json(feirantes)
  } catch (error) {
    res.status(500).json({ erro: error })
  }
})

// Rota de Consulta de feirante pelo Id, retorna um OBJETO, não um ARRAY
router.get("/:id", async (req, res) => {
  const { id } = req.params

  try {
    const feirante = await prisma.feirante.findUnique({
      where: { id: Number(id)},
    })
    res.status(200).json(feirante)
  } catch (error) {
    res.status(400).json(error)
  }
})

router.get("/:id/mercadorias", async (req, res) => {
  
  const { id } = req.params;

  try {
    const mercadoriasDoFeirante = await prisma.mercadoria.findMany({
      
      where: {
        
        feirante_id: Number(id),
      },
    
      select: {
        id: true,
        nome: true,
        preco: true,
        quantidade: true,
      },
    });

    res.status(200).json(mercadoriasDoFeirante);
  } catch (error) {
    res.status(500).json({ erro: error });
  }
});
export default router
