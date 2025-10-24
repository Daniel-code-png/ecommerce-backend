import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v2 as cloudinary } from 'cloudinary';

const app = express();

// Configurar Cloudinary (servicio de imágenes GRATIS)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Middlewares
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Permitir imágenes base64

// Conexión MongoDB con cache
let cachedDb = null;
async function connectDB() {
  if (cachedDb) return cachedDb;
  const conn = await mongoose.connect(process.env.MONGODB_URI, { bufferCommands: false });
  cachedDb = conn;
  console.log('✅ Conectado a MongoDB');
  return conn;
}

// MODELOS (igual que antes)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  category: { type: String, required: true, trim: true },
  stock: { type: Number, required: true, min: 0, default: 0 },
  image: { type: String, default: 'https://via.placeholder.com/300x300?text=Sin+Imagen' },
  sold: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    name: String,
    price: Number,
    quantity: { type: Number, required: true, min: 1 },
    image: String
  }],
  totalAmount: { type: Number, required: true, min: 0 },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'cancelled'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Product = mongoose.models.Product || mongoose.model('Product', productSchema);
const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);

// MIDDLEWARE AUTENTICACIÓN
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(401).json({ message: 'Token inválido' });
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token inválido' });
  }
};

const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Requiere permisos de admin' });
  }
  next();
};

// ==================== RUTAS AUTH ====================
app.post('/api/auth/register', async (req, res) => {
  await connectDB();
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El email ya está registrado' });
    
    const user = new User({ name, email, password, isAdmin: false });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  await connectDB();
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Credenciales inválidas' });
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Credenciales inválidas' });
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({
    user: { id: req.user._id, name: req.user.name, email: req.user.email, isAdmin: req.user.isAdmin }
  });
});

// ==================== RUTAS PRODUCTOS ====================
app.get('/api/products', async (req, res) => {
  await connectDB();
  try {
    const { category, search } = req.query;
    let query = {};
    if (category) query.category = category;
    if (search) query.name = { $regex: search, $options: 'i' };
    
    const products = await Product.find(query).sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/products/categories/list', async (req, res) => {
  await connectDB();
  try {
    const categories = await Product.distinct('category');
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  await connectDB();
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// CREAR PRODUCTO - Recibe imagen en Base64 y la sube a Cloudinary
app.post('/api/products', authenticate, isAdmin, async (req, res) => {
  await connectDB();
  try {
    const { name, description, price, category, stock, imageBase64 } = req.body;
    
    let imageUrl = 'https://via.placeholder.com/300x300?text=Sin+Imagen';
    
    // Si viene imagen en base64, subirla a Cloudinary
    if (imageBase64) {
      try {
        const uploadResult = await cloudinary.uploader.upload(imageBase64, {
          folder: 'ecommerce/products',
          transformation: [
            { width: 500, height: 500, crop: 'limit' }
          ]
        });
        imageUrl = uploadResult.secure_url;
      } catch (uploadError) {
        console.error('Error al subir imagen:', uploadError);
        return res.status(400).json({ message: 'Error al subir imagen' });
      }
    }

    const product = new Product({
      name,
      description,
      price: Number(price),
      category,
      stock: Number(stock),
      image: imageUrl
    });

    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ACTUALIZAR PRODUCTO
app.put('/api/products/:id', authenticate, isAdmin, async (req, res) => {
  await connectDB();
  try {
    const { name, description, price, category, stock, imageBase64 } = req.body;
    
    const updateData = {
      name,
      description,
      price: Number(price),
      category,
      stock: Number(stock)
    };

    // Si viene nueva imagen, subirla
    if (imageBase64) {
      try {
        const uploadResult = await cloudinary.uploader.upload(imageBase64, {
          folder: 'ecommerce/products',
          transformation: [
            { width: 500, height: 500, crop: 'limit' }
          ]
        });
        updateData.image = uploadResult.secure_url;
      } catch (uploadError) {
        console.error('Error al subir imagen:', uploadError);
        return res.status(400).json({ message: 'Error al subir imagen' });
      }
    }

    const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/products/:id', authenticate, isAdmin, async (req, res) => {
  await connectDB();
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ message: 'Producto eliminado' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==================== RUTAS ÓRDENES ====================
app.post('/api/orders', authenticate, async (req, res) => {
  await connectDB();
  try {
    const { items } = req.body;
    if (!items || items.length === 0) {
      return res.status(400).json({ message: 'El carrito está vacío' });
    }

    let totalAmount = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) return res.status(404).json({ message: `Producto no encontrado` });
      if (product.stock < item.quantity) {
        return res.status(400).json({ message: `Stock insuficiente para ${product.name}` });
      }

      totalAmount += product.price * item.quantity;
      orderItems.push({
        product: product._id,
        name: product.name,
        price: product.price,
        quantity: item.quantity,
        image: product.image
      });

      product.stock -= item.quantity;
      product.sold += item.quantity;
      await product.save();
    }

    const order = new Order({
      user: req.user._id,
      items: orderItems,
      totalAmount,
      status: 'completed'
    });

    await order.save();
    res.status(201).json({ message: '¡Pago procesado!', order });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/orders/my-orders', authenticate, async (req, res) => {
  await connectDB();
  try {
    const orders = await Order.find({ user: req.user._id })
      .populate('items.product')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/orders/all', authenticate, isAdmin, async (req, res) => {
  await connectDB();
  try {
    const orders = await Order.find()
      .populate('user', 'name email')
      .populate('items.product')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==================== RUTAS ESTADÍSTICAS ====================
app.get('/api/stats', authenticate, isAdmin, async (req, res) => {
  await connectDB();
  try {
    const totalSalesResult = await Order.aggregate([
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);
    const totalSales = totalSalesResult[0]?.total || 0;
    
    const totalOrders = await Order.countDocuments();
    const totalUsers = await User.countDocuments({ isAdmin: false });
    const totalProducts = await Product.countDocuments();
    const topProducts = await Product.find().sort({ sold: -1 }).limit(5);
    
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
    
    const salesByMonth = await Order.aggregate([
      { $match: { createdAt: { $gte: sixMonthsAgo } } },
      {
        $group: {
          _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
          total: { $sum: '$totalAmount' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);
    
    const monthNames = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'];
    const formattedSalesByMonth = salesByMonth.map(item => ({
      month: `${monthNames[item._id.month - 1]} ${item._id.year}`,
      total: item.total,
      orders: item.count
    }));
    
    const salesByCategory = await Order.aggregate([
      { $unwind: '$items' },
      { $lookup: { from: 'products', localField: 'items.product', foreignField: '_id', as: 'productInfo' } },
      { $unwind: '$productInfo' },
      {
        $group: {
          _id: '$productInfo.category',
          total: { $sum: { $multiply: ['$items.price', '$items.quantity'] } },
          quantity: { $sum: '$items.quantity' }
        }
      },
      { $sort: { total: -1 } }
    ]);
    
    const formattedSalesByCategory = salesByCategory.map(item => ({
      category: item._id,
      total: item.total,
      quantity: item.quantity
    }));
    
    const recentOrders = await Order.find()
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(5);
    
    res.json({
      overview: { totalSales, totalOrders, totalUsers, totalProducts },
      topProducts,
      salesByMonth: formattedSalesByMonth,
      salesByCategory: formattedSalesByCategory,
      recentOrders
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api', (req, res) => {
  res.json({ message: '🚀 API E-commerce funcionando correctamente' });
});

app.get('/', (req, res) => {
  res.json({ message: '🚀 API E-commerce funcionando correctamente' });
});

export default app;