export class Encoder{
    key: string;
    seed: number;
    method: string;
    a_code="a".charCodeAt(0)
    A_code="A".charCodeAt(0)
    z_code="z".charCodeAt(0)
    constructor(key="a", method="vigenere",seed=0){
        key=key.toLowerCase()
        this.key=this.Delete_unsupported(key)
        this.method=method
        this.seed=seed
    }
    private Delete_unsupported(key:string):string{
      key=key.toLowerCase()
      let s_key="";
      for(let i=0;i<key.length;i++){
        if (key.charCodeAt(i)>=this.a_code && key.charCodeAt(i)<=this.z_code){
          s_key+=key[i]
        }
      }
      return s_key
    }
    Encrypt(text:string):string{
        if (this.method=="gamm"){
            this.key=this.Generate(text.length)
        }
        let res=""
        const text_c=text
        text=text.toLowerCase()
        for (let i = 0; i < text.length; i++) {
            if (text.charCodeAt(i)>=this.a_code && text.charCodeAt(i)<=this.z_code){
                res+=String.fromCharCode((text.charCodeAt(i)+this.key.charCodeAt(i%this.key.length)-2*this.a_code)%(this.z_code-this.a_code+1)+this.a_code)
                console.log(text.charCodeAt(i),this.key.charCodeAt(i%this.key.length),(text.charCodeAt(i)+this.key.charCodeAt(i%this.key.length))%(this.z_code-this.a_code+1)+this.a_code)
            }
            else{
            res+=text[i]
            }
        }
        return this.ToUpper(res,text_c)
    }
    Decode(text: string):string{
        if (this.method=="gamm"){
            this.key=this.Generate(text.length,this.seed)
        }
        let res=""
        const text_c=text
        text=text.toLowerCase()
        for (let i = 0; i < text.length; i++) {
            if (text.charCodeAt(i)>=this.a_code && text.charCodeAt(i)<=this.z_code){
            const code=text.charCodeAt(i)-this.key.charCodeAt(i%this.key.length)
            res+=String.fromCharCode((code+(this.z_code-this.a_code+1))%(this.z_code-this.a_code+1)+this.a_code)
            }
            else{
                res+=text[i]
            }
        }
        return this.ToUpper(res,text_c)
    }
    ToUpper(text: string, original: string): string{
        let res=""
        for (let i = 0; i < text.length; i++) {
            let s;
            if (original.charCodeAt(i)<this.a_code && original.charCodeAt(i)>=this.A_code){
                s=text[i]
                s=s?.toUpperCase()
            }
            else {
                s=text[i]
            }
            res+=s
        }
        return res
    }
    private Generate(length:number,seed=0):string{
        let rng;
        if (seed!=0){
            rng = new Lcg32(seed);
        }
        else{
            rng = new Lcg32();
            this.seed=rng.getSeed();
        }
        let res=""
        for (let i = 0; i < length; i++) {
            res+=String.fromCharCode(rng.nextRangeInt(this.a_code,this.z_code))
        }
        return res
    }
}

class Lcg32 {
  private state: number;

  constructor(seed: number = Date.now()) {
    this.state = seed >>> 0;
  }

  getSeed(): number{
    return this.state
  }

  nextUint32(): number {
    this.state = (Math.imul(1664525, this.state) + 1013904223) >>> 0;
    return this.state;
  }

  nextInt(maxExclusive: number): number {
    if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
      throw new Error("maxExclusive must be a positive integer");
    }

    const max = maxExclusive >>> 0;
    const range = 0x1_0000_0000;
    const limit = range - (range % max);

    let x: number;
    do {
      x = this.nextUint32();
    } while (x >= limit);

    return x % max;
  }

  nextRangeInt(min: number, max: number): number {
    if (!Number.isInteger(min) || !Number.isInteger(max) || min > max) {
      throw new Error("min/max must be integers and min <= max");
    }
    const span = (max - min + 1);
    return min + this.nextInt(span);
  }
}
