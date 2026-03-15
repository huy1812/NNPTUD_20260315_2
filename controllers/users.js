let userModel = require("../schemas/users");
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let { SignToken } = require('../utils/authHandler')

module.exports = {
    CreateAnUser: async function (username, password, email, role, fullName, avatarUrl, status, loginCount) {
        // Password will be hashed by schema pre('save') middleware
        let newItem = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newItem.save();
        return newItem;
    },
    GetAllUser: async function () {
        return await userModel
            .find({ isDeleted: false })
    },
    GetUserById: async function (id) {
        try {
            return await userModel
                .find({
                    isDeleted: false,
                    _id: id
                })
        } catch (error) {
            return false;
        }
    },
    QueryLogin: async function (username, password) {
        if (!username || !password) {
            return false;
        }
        let user = await userModel.findOne({
            username: username,
            isDeleted: false
        })
        if (user) {
            if (bcrypt.compareSync(password, user.password)) {
                return SignToken(user.id)
            } else {
                return false;
            }
        } else {
            return false;
        }
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        if (!userId || !oldPassword || !newPassword) {
            return { success: false, message: "Thông tin không đầy đủ" };
        }
        
        let user = await userModel.findOne({
            _id: userId,
            isDeleted: false
        });
        
        if (!user) {
            return { success: false, message: "Không tìm thấy người dùng" };
        }
        
        // Kiểm tra password cũ
        if (!bcrypt.compareSync(oldPassword, user.password)) {
            return { success: false, message: "Mật khẩu cũ không chính xác" };
        }
        
        // Cập nhật mật khẩu - schema pre('save') sẽ hash nó
        user.password = newPassword;
        await user.save();
        
        return { success: true, message: "Đổi mật khẩu thành công" };
    }
}