import { PrismaClient } from '@prisma/client'
import { Router } from 'express'
import { z } from 'zod'
import multer from 'multer'
import { CloudinaryStorage } from 'multer-storage-cloudinary'
import { v2 as cloudinary } from 'cloudinary';


const prisma = new PrismaClient()
const router = Router()

const fotoSchema = z.object({
  descricao: z.string().min(5,
    { message: "mecadoria deve possuir, no mínimo, 5 caracteres" }),
  feirante_id: z.coerce.number(),
  mercadoria_id: z.coerce.number(),
  
})

router.get("/", async (req, res) => {
  try {
    const fotos = await prisma.fotoMercadoria.findMany({
      include: {
        mercadoria: true,
        feirante: true,
      }
    })
    res.status(200).json(fotos)
  } catch (error) {
    res.status(500).json({ erro: error })
  }
})

// Configuration
cloudinary.config({
  cloud_name: 'djvtwvsqy',
  api_key: '411775921765867',
  api_secret: 'MMvDqCmxT9TcmvscHMJzVL_yu4M' // Click 'View API Keys' above to copy your API secret
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    return {
      folder: 'revenda',
      allowed_formats: ['jpg', 'png', 'jpeg'], // supports promises as well
      public_id: `${Date.now()}-${file.originalname.split(".")[0]}`
    }
  },
});

const upload = multer({ storage })

router.post("/", upload.single('imagem'), async (req, res) => {

  console.log("ARQUIVO COMPLETO:", JSON.stringify(req.file, null, 2));

  const valida = fotoSchema.safeParse(req.body)
  // if (!valida.success) {
  //   res.status(400).json({ erro: valida.error.format() })
  //   return
  // }
  if (!valida.success) {
    console.log(valida.error)
    res.status(400).json({ erro: JSON.parse(JSON.stringify(valida.error)) })
    return
  }

  if (!req.file || !req.file.path) {
    res.status(400).json({ erro: "Imagem não enviada" })
    return
  }

  const { descricao, feirante_id, mercadoria_id } = valida.data
  // const urlFoto_Mercadoria = req.file.path

  const urlFoto_Mercadoria = (req.file as any)?.path || (req.file as any)?.url;

  if (!urlFoto_Mercadoria) {
    console.log("ERRO: req.file não possui URL válida", req.file);
    return res.status(500).json({ erro: "Falha ao obter a URL da imagem enviada." });
  }



  try {
    const foto = await prisma.fotoMercadoria.create({
      data: {
        descricao, feirante_id, mercadoria_id, url: urlFoto_Mercadoria,
      }
    })
    res.status(201).json(foto)
  } catch (error) {
    res.status(400).json({ error })
  }
})

// router.delete("/:id", async (req, res) => {
//   const { id } = req.params

//   try {
//     const foto = await prisma.foto.delete({
//       where: { id: Number(id) }
//     })
//     res.status(200).json(foto)
//   } catch (error) {
//     res.status(400).json({ erro: error })
//   }
// })

// router.put("/:id", async (req, res) => {
//   const { id } = req.params

//   const valida = fotoSchema.safeParse(req.body)
//   if (!valida.success) {
//     res.status(400).json({ erro: valida.error })
//     return
//   }

//   const { modelo, ano, preco, km, foto, acessorios,
//     destaque, combustivel, marcaId } = valida.data

//   try {
//     const carro = await prisma.carro.update({
//       where: { id: Number(id) },
//       data: {
//         modelo, ano, preco, km, foto, acessorios,
//         destaque, combustivel, marcaId
//       }
//     })
//     res.status(200).json(carro)
//   } catch (error) {
//     res.status(400).json({ error })
//   }
// })

// router.get("/pesquisa/:termo", async (req, res) => {
//   const { termo } = req.params

//   // tenta converter para número
//   const termoNumero = Number(termo)

//   // is Not a Number, ou seja, se não é um número: filtra por texto
//   if (isNaN(termoNumero)) {
//     try {
//       const carros = await prisma.carro.findMany({
//         include: {
//           marca: true,
//         },
//         // mode sensitive (Para não diferenciar maiuscula de minúsculas)
//         // necessário no PostgreSQL (NO MySQL é o padrão)
//         where: {
//           OR: [
//             { modelo: { contains: termo, mode: "insensitive" } },
//             { marca: { nome: { equals: termo, mode: "insensitive" } } }
//           ]
//         }
//       })
//       res.status(200).json(carros)
//     } catch (error) {
//       res.status(500).json({ erro: error })
//     }
//   } else {
//     if (termoNumero <= 3000) {
//       try {
//         const carros = await prisma.carro.findMany({
//           include: {
//             marca: true,
//           },
//           where: { ano: termoNumero }
//         })
//         res.status(200).json(carros)
//       } catch (error) {
//         res.status(500).json({ erro: error })
//       }  
//     } else {
//       try {
//         const carros = await prisma.carro.findMany({
//           include: {
//             marca: true,
//           },
//           where: { preco: { lte: termoNumero } }
//         })
//         res.status(200).json(carros)
//       } catch (error) {
//         res.status(500).json({ erro: error })
//       }
//     }
//   }
// })

// // Rota de Consulta de veículo pelo Id, retorna um OBJETO, não um ARRAY
// router.get("/:id", async (req, res) => {
//   const { id } = req.params

//   try {
//     const carro = await prisma.carro.findUnique({
//       where: { id: Number(id)},
//       include: {
//         marca: true
//       }
//     })
//     res.status(200).json(carro)
//   } catch (error) {
//     res.status(400).json(error)
//   }
// })

export default router
