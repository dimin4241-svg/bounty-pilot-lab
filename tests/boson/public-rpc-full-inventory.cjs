'use strict';
const fs=require('fs');
const {JsonRpcProvider,Interface,Contract,getAddress}=require('ethers');
const diamond='0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5';
const multi='0xca11bde05977b3631167028862be2a173976ca11';
const providers={
 '137':['https://polygon-bor-rpc.publicnode.com','https://polygon-rpc.com'],
 '1':['https://ethereum-rpc.publicnode.com'],
 '8453':['https://base-rpc.publicnode.com','https://mainnet.base.org'],
 '10':['https://optimism-rpc.publicnode.com'],
 '42161':['https://arbitrum-one-rpc.publicnode.com']};
const abi=new Interface([
 'function getNextOfferId() view returns(uint256)',
 'function getOffer(uint256) view returns(bool,(uint256,uint256,uint256,uint256,uint256,uint256,address,uint8,uint8,string,string,bool,uint256,(address[],uint256[])[],uint256),(uint256,uint256,uint256,uint256),(uint256,uint256,uint256),(uint256,uint256,uint256,uint256,address),(uint256,uint256))']);
const multiabi=['function aggregate3(tuple(address target,bool allowFailure,bytes callData)[] calls) payable returns (tuple(bool success,bytes returnData)[] returnData)'];
async function measure(chain,urls){
 const s={chain,declared:0,inspected:0,notDecoded:0,nonzero:[],status:'not-checked',providerErrors:[]};
 for(const url of urls){
  try{
   const p=new JsonRpcProvider(url,Number(chain),{staticNetwork:true,batchMaxCount:1});
   s.block=await p.getBlockNumber();
   if((await p.getCode(multi))==='0x')throw Error('No Multicall3');
   const c=new Contract(multi,multiabi,p);
   const next=Number(abi.decodeFunctionResult('getNextOfferId',await p.call({to:diamond,data:abi.encodeFunctionData('getNextOfferId',[])}))[0]);
   s.declared=Math.max(0,next-1);
   try { s.protocolVersion = String(await (new Contract(diamond,['function getVersion() view returns (string)'],p)).getVersion()); } catch(e) { s.protocolVersion='unavailable'; }
   for(let first=1;first<next;first+=24){
    const ids=Array.from({length:Math.min(24,next-first)},(_,i)=>first+i);
    const calls=ids.map(id=>({target:diamond,allowFailure:true,callData:abi.encodeFunctionData('getOffer',[id])}));
    let items;
    try{items=await c.aggregate3.staticCall(calls,{gasLimit:18000000});}
    catch(e){s.providerErrors.push('chunk:'+first+' '+String(e.shortMessage||e.message).slice(0,100));s.status='partial-aggregate-failure';break;}
    for(let i=0;i<ids.length;i++){
     if(!items[i].success){s.notDecoded++;continue;}
     try{
      const r=abi.decodeFunctionResult('getOffer',items[i].returnData);
      s.inspected++;
      if(r[0]&&r[4][4]!=='0x0000000000000000000000000000000000000000')
       s.nonzero.push({id:ids[i],mutualizer:getAddress(r[4][4]),sellerId:String(r[1][1]),resolverId:String(r[4][0]),fee:String(r[4][2])});
     }catch(e){s.notDecoded++;}
    }
   }
   if(s.inspected===s.declared)s.status='complete';
   else if(s.status!=='partial-aggregate-failure')s.status='partial';
   s.provider=url;break;
  }catch(e){s.providerErrors.push(String(e.shortMessage||e.message).slice(0,100));}
 }
 console.log('BOSON_FULL_READONLY '+JSON.stringify(s));
 return s;
}
(async()=>{
 const results=[];
 for(const [chain,urls] of Object.entries(providers))results.push(await measure(chain,urls));
 fs.writeFileSync(process.env.BOSON_READONLY_OUTPUT,JSON.stringify({date:new Date().toISOString(),method:'read-only eth_call; no transactions',diamond,results},null,2));
})();