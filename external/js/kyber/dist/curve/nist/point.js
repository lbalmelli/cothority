"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bn_js_1 = __importDefault(require("bn.js"));
const crypto_1 = require("crypto");
const constants_1 = require("../../constants");
/**
* Represents a Point on the nist curve
*
* The value of the parameters is expected in little endian form if being
* passed as a buffer
*/
class NistPoint {
    constructor(curve, x, y) {
        if (x instanceof Buffer) {
            x = new bn_js_1.default(x, 16, "le");
        }
        if (y instanceof Buffer) {
            y = new bn_js_1.default(y, 16, "le");
        }
        // the point reference is stored in an object to make set()
        // consistent.
        this.ref = {
            curve: curve,
            point: curve.curve.point(x, y)
        };
    }
    /** @inheritdoc */
    string() {
        return this.toString();
    }
    inspect() {
        return this.toString();
    }
    /**
    * Returns the little endian representation of the y coordinate of
    * the Point
    * @returns the string representation
    */
    toString() {
        if (this.ref.point.inf) {
            return "(0,0)";
        }
        return ("(" +
            this.ref.point.x.fromRed().toString(10) +
            "," +
            this.ref.point.y.fromRed().toString(10) +
            ")");
    }
    /** @inheritdoc */
    equal(p2) {
        if (this.ref.point.isInfinity() ^ p2.ref.point.isInfinity()) {
            return false;
        }
        if (this.ref.point.isInfinity() & p2.ref.point.isInfinity()) {
            return true;
        }
        return (this.ref.point.x.cmp(p2.ref.point.x) === 0 &&
            this.ref.point.y.cmp(p2.ref.point.y) === 0);
    }
    /** @inheritdoc */
    set(p2) {
        this.ref = p2.ref;
        return this;
    }
    /** @inheritdoc */
    clone() {
        const point = this.ref.point;
        return new NistPoint(this.ref.curve, point.x, point.y);
    }
    /** @inheritdoc */
    null() {
        this.ref.point = this.ref.curve.curve.point(null, null);
        return this;
    }
    /** @inheritdoc */
    base() {
        const g = this.ref.curve.curve.g;
        this.ref.point = this.ref.curve.curve.point(g.x, g.y);
        return this;
    }
    /** @inheritdoc */
    embedLen() {
        // Reserve the most-significant 8 bits for pseudo-randomness.
        // Reserve the least-significant 8 bits for embedded data length.
        // (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
        return (this.ref.curve.curve.p.bitLength() - 8 - 8) >> 3;
    }
    /** @inheritdoc */
    embed(data, callback) {
        let l = this.ref.curve.coordLen();
        let dl = this.embedLen();
        if (data.length > dl) {
            throw new Error("data.length > dl");
        }
        if (dl > data.length) {
            dl = data.length;
        }
        callback = callback || crypto_1.randomBytes;
        while (true) {
            const bitLen = this.ref.curve.curve.p.bitLength();
            const buffLen = bitLen >> 3;
            let buff = callback(buffLen);
            let highbits = bitLen & 7;
            if (highbits != 0) {
                buff[0] &= ~(0xff << highbits);
            }
            if (dl > 0) {
                buff[l - 1] = dl; // encode length in lower 8 bits
                data.copy(buff, l - dl - 1);
            }
            //console.log(bytes);
            let x = new bn_js_1.default(buff, 16, "be");
            if (x.cmp(this.ref.curve.curve.p) > 0) {
                continue;
            }
            let xRed = x.toRed(this.ref.curve.curve.red);
            let aX = xRed.redMul(new bn_js_1.default(this.ref.curve.curve.a));
            // y^2 = x^3 + ax + b
            let y2 = xRed.redSqr()
                .redMul(xRed)
                .redAdd(aX)
                .redAdd(new bn_js_1.default(this.ref.curve.curve.b));
            let y = y2.redSqrt();
            let b = callback(1);
            if ((b[0] & 0x80) !== 0) {
                y = this.ref.curve.curve.p.sub(y).toRed(this.ref.curve.curve.red);
            }
            // check if it is a valid point
            let y2t = y.redSqr();
            if (y2t.cmp(y2) === 0) {
                return new NistPoint(this.ref.curve, xRed, y);
            }
        }
    }
    /** @inheritdoc */
    data() {
        const l = this.ref.curve.coordLen();
        let b = Buffer.from(this.ref.point.x.fromRed().toArray("be", l));
        const dl = b[l - 1];
        if (dl > this.embedLen()) {
            throw new Error("invalid embed data length");
        }
        return b.slice(l - dl - 1, l - 1);
    }
    /** @inheritdoc */
    add(p1, p2) {
        const point = p1.ref.point;
        this.ref.point = this.ref.curve.curve
            .point(point.x, point.y)
            .add(p2.ref.point);
        return this;
    }
    /** @inheritdoc */
    sub(p1, p2) {
        const point = p1.ref.point;
        this.ref.point = this.ref.curve.curve
            .point(point.x, point.y)
            .add(p2.ref.point.neg());
        return this;
    }
    /** @inheritdoc */
    neg(p) {
        this.ref.point = p.ref.point.neg();
        return this;
    }
    /** @inheritdoc */
    mul(s, p) {
        p = p || null;
        const arr = s.ref.arr.fromRed();
        this.ref.point =
            p !== null ? p.ref.point.mul(arr) : this.ref.curve.curve.g.mul(arr);
        return this;
    }
    /** @inheritdoc */
    pick(callback) {
        callback = callback || null;
        return this.embed(Buffer.from([]), callback);
    }
    /** @inheritdoc */
    marshalSize() {
        // uncompressed ANSI X9.62 representation
        return this.ref.curve.pointLen();
    }
    /** @inheritdoc */
    marshalBinary() {
        const byteLen = this.ref.curve.coordLen();
        const buf = Buffer.allocUnsafe(this.ref.curve.pointLen());
        buf[0] = 4; // uncompressed point
        let xBytes = Buffer.from(this.ref.point.x.fromRed().toArray("be"));
        xBytes.copy(buf, 1 + byteLen - xBytes.length);
        let yBytes = Buffer.from(this.ref.point.y.fromRed().toArray("be"));
        yBytes.copy(buf, 1 + 2 * byteLen - yBytes.length);
        return buf;
    }
    /** @inheritdoc */
    unmarshalBinary(bytes) {
        const byteLen = this.ref.curve.coordLen();
        if (bytes.length != 1 + 2 * byteLen) {
            throw new Error();
        }
        // not an uncompressed point
        if (bytes[0] != 4) {
            throw new Error("unmarshalBinary only accepts uncompressed point");
        }
        let x = new bn_js_1.default(bytes.slice(1, 1 + byteLen), 16);
        let y = new bn_js_1.default(bytes.slice(1 + byteLen), 16);
        if (x.cmp(constants_1.zeroBN) === 0 && y.cmp(constants_1.zeroBN) === 0) {
            this.ref.point = this.ref.curve.curve.point(null, null);
            return;
        }
        this.ref.point = this.ref.curve.curve.point(x, y);
        if (!this.ref.curve.curve.validate(this.ref.point)) {
            throw new Error("point is not on curve");
        }
    }
}
exports.default = NistPoint;