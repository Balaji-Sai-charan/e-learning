import express from 'express';
import { login, myProfile, register, verifyUser } from '../controllers/user.js';
import { isAuth } from '../middlewares/isAuth.js';

const router = express.Router();

router.post('/user/register',register);
router.post("/user/verify",verifyUser);
router.post("/user/login",login);
router.get("/user/me",isAuth,myProfile)
export default router