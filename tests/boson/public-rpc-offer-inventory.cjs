'use strict';
// Strictly read-only public-RPC inspection of Boson deployment metadata. No transactions.
const {JsonRpcProvider, Contract} = require('ethers');
const chainMap={
'137':['https://polygon-bor-rpc.publicnode.com','https://polygon-rpc.com'],
'1':['https://ethereum-rpc.publicnode.com','https://cloudflare-eth.com'],
'8453':['https://base-rpc.publicnode.com','https://mainnet.base.org'],
'10':['https://optimism-rpc.publicnode.com','https://mainnet.optimism.io'],
'42161':['https://arbitrum-one-rpc.publicnode.com','https://arb1.arbitrum.io/rpc']};
const diamond='0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5';
const abi=[
'function getNextOfferId() view returns (uint256)',
'function getNextExchangeId() view returns (uint256)',
'function getOffer(uint256) view returns (bool,(uint256,uint256,uint256,uint256,uint256,uint256,address,uint8,uint8,string,string,bool,uint256,(address[],uint256[])[],uint256),(uint256,uint256,uint256,uint256),(uint256,uint256,uint256),(uint256,uint256,uint256,uint256,address),(uint256,uint256))'];
const sleep=(ms)=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
let results=[];
for(const [chain,urls] of Object.entries(chainMap)){
 let record={chain,checked:0,errors:[],nonzero:[],status:'unknown'};
 for(const url of urls){
  try{
   const p=new JsonRpcProvider(url,Number(chain),{staticNetwork:true,batchMaxCount:1});
   const block=await Promise.race([p.getBlockNumber(),new Promise((_,reject)=>setTimeout(()=>reject(Error('timeout')),10000))]);
   const code=await p.getCode(diamond);
   if(code==='0x')throw Error('no code at address');
   const c=new Contract(diamond,abi,p);
   const next=Number(await c.getNextOfferId());
   const exchanges=Number(await c.getNextExchangeId());
   record.state={block,nextOfferId:next,nextExchangeId:exchanges};
   const indices=new Set();
   for(let i=1;i<=Math.min(20,next-1);i++)indices.add(i);
   for(let i=Math.max(1,next-20);i<next;i++)indices.add(i);
   for(const offerId of indices){
    try{
     const offer=await c.getOffer(offerId);
     record.checked++;
     if(offer[0] && offer[4].mutualizerAddress!=='0x0000000000000000000000000000000000000000')
      record.nonzero.push({offerId,address:offer[4].mutualizerAddress,sellerId:String(offer[1].sellerId),fee:String(offer[4].feeAmount),resolverId:String(offer[4].disputeResolverId)});
    }catch(e){record.failedOffers=(record.failedOffers||0)+1;}
    await sleep(150);
   }
   record.status='read-ok';
   record.provider=url;
   break;
  }catch(e){record.errors.push({provider:url,error:String(e.message||e).slice(0,160)});}
 }
 results.push(record);
 console.log('BOSON_READONLY '+JSON.stringify(record));
}
require('fs').writeFileSync(process.env.BOSON_READONLY_OUTPUT,JSON.stringify({capturedAt:new Date().toISOString(),diamond,method:'read-only eth_call + eth_getCode',results},null,2));
})();