<?php
/**
 * walletWeixinUtil
 * +----------------------------+
 * +         公用类方法         +
 * +----------------------------+
 * function getRealIp     得到 ip地址
 * function getNonceStr   得到 随机字符串
 * function curl_post_ssl 带curl 带证书请求
 * function _getSign      得到带签名的新的xml
 * @version v1.0
 * creat_time  2015-06-04 22:17 
 */
class walletWeixinUtil
{
    /**
     * 获取用户 的ip
     * @return ip
     */
    public static function getRealIp() {
        $ip = "Unknown";

        if (isset($_SERVER["HTTP_X_REAL_IP"]) && !empty($_SERVER["HTTP_X_REAL_IP"])) {
            $ip = $_SERVER["HTTP_X_REAL_IP"];
        }
        elseif (isset($HTTP_SERVER_VARS["HTTP_X_FORWARDED_FOR"]) && !empty($HTTP_SERVER_VARS["HTTP_X_FORWARDED_FOR"])) {
            $ip = $HTTP_SERVER_VARS["HTTP_X_FORWARDED_FOR"];
        }
        elseif (isset($HTTP_SERVER_VARS["HTTP_CLIENT_IP"]) && !empty($HTTP_SERVER_VARS["HTTP_CLIENT_IP"])) {
            $ip = $HTTP_SERVER_VARS["HTTP_CLIENT_IP"];
        }
        elseif (isset($HTTP_SERVER_VARS["REMOTE_ADDR"]) && !empty($HTTP_SERVER_VARS["REMOTE_ADDR"])) {
            $ip = $HTTP_SERVER_VARS["REMOTE_ADDR"];
        }
        elseif (getenv("HTTP_X_FORWARDED_FOR")) {
            $ip = getenv("HTTP_X_FORWARDED_FOR");
        }
        elseif (getenv("HTTP_CLIENT_IP")) {
            $ip = getenv("HTTP_CLIENT_IP");
        }
        elseif (getenv("REMOTE_ADDR")) {
            $ip = getenv("REMOTE_ADDR");
        }

        if( $ip == 'Unknown'){
            // 调试信息
            self:: debugErrorSendWx('获取不到ip地址', $_SERVER );            
        }
        return $ip;
    }

    /**
     * 产生随机字符串，不长于32位
     * @param int $length
     * @return 产生的随机字符串
     */
    public static function getNonceStr($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str ="";
        for ( $i = 0; $i < $length; $i++ )  {
            $str .= substr($chars, mt_rand(0, strlen($chars)-1), 1);
        }
        return $str;
    }

    /**
     * 带证书请求xml 接口
     * @param   $url     请求的接口
     * @param   $vars    xml数据
     * @param   $second  最大超时时间 s
     * @param   $aHeader 请求头
     * @return 产生的随机字符串
     */
    public static function curl_post_ssl($url, $vars, $second=30,$aHeader=array())
    {
        $ch = curl_init();
        //超时时间
        curl_setopt($ch,CURLOPT_TIMEOUT,$second);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, 1);
        //这里设置代理，如果有的话
        //curl_setopt($ch,CURLOPT_PROXY, '10.206.30.98');
        //curl_setopt($ch,CURLOPT_PROXYPORT, 8080);
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,false);

        //以下两种方式需选择一种

        //第一种方法，cert 与 key 分别属于两个.pem文件
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLCERTTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLCERT, WxPayConf_pub::SSLCERT_PATH );
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLKEYTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLKEY, WxPayConf_pub::SSLKEY_PATH );

         curl_setopt($ch,CURLOPT_CAINFO, WxPayConf_pub::SSLROOTCA_PATH );
        //第二种方式，两个文件合成一个.pem文件
   		//  curl_setopt($ch,CURLOPT_SSLCERT,getcwd().'/all.pem');

        if( count($aHeader) >= 1 ){
            curl_setopt($ch, CURLOPT_HTTPHEADER, $aHeader);
        }

        curl_setopt($ch,CURLOPT_POST, 1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$vars);
        $data = curl_exec($ch);
        if($data){
            curl_close($ch);
            $debugArray = @simplexml_load_string($data,NULL,LIBXML_NOCDATA);
            $debugArrayNew['状态'] =  $debugArray['return_code'];
            $debugArrayNew['返回信息'] =  @$debugArray['return_msg'];

            // 调试信息
            //self:: debugErrorSendWx('发红包微信接口返回', $debugArrayNew );

            return $data;

        }
        else {
            $error = curl_errno($ch);
            echo "call faild, errorCode:$error\n";
            // 调试信息
            self:: debugErrorSendWx('sendWallet_app => curl_post_ssl出错', array('error' => $error) );
            curl_close($ch);
            return false;
        }
    }

    /**
     * +---------------------------+
     * +       生成支付签名        +
     * +---------------------------+
     * @param  $xmlData  xml数据
     * @return 带上签名的xmlData
     */
    public static function _getSign($xmlData){
        $res = @simplexml_load_string($xmlData,NULL,LIBXML_NOCDATA);
        $res = json_decode(json_encode($res),true);
        unset($res['sign']);
        ksort($res);
        $stringA = "";
        foreach ($res as $key => $value) {
            if (!empty($value)){
                $stringA .= "{$key}=$value&";
            }
        }

        $stringSignTemp="{$stringA}key=". WxPayConf_pub::KEY;
        $sign = md5($stringSignTemp);

        $xmlData = str_replace("{sign}", $sign, $xmlData);
        return $xmlData;
    }

    //签名检查算法  signature、timestamp、nonce

    /**
     * +---------------------------+
     * +       生成验证签名        +
     * +---------------------------+
     * @param  $signature   生成的签名
     * @param  $timestamp   生成的签名
     * @param  $nonce       生成的签名
     * @param  $privateKey  生成的签名
     * @return bool  true or false
     */    
    public static function checkSignature($signature,$timestamp,$nonce,$privateKey = '') {
        if( empty($signature) ){return false;}

        $time = time();
        if ($time - $timestamp > 10) {
            return false;
        }
 
        $token = empty($privateKey) ? WxPayConf_pub::privateKey : $privateKey;
        $tmpArr = array($token, $timestamp, $nonce);
        sort($tmpArr, SORT_STRING);
        $tmpStr = implode( $tmpArr );
        $tmpStr = sha1( $tmpStr );
 
        if( $tmpStr == $signature ){
            return true;
        }else{
            return false;
        }
    }



    /**
     * 调试微信接收信息公用方法
     * @param $title 标题
     * @param $array 要发送的数据
     * @return 微信官方返回的数据
     */     
    public static function debugErrorSendWx($title = "调试信息", $array = array() ){

        if (WxPayConf_pub::DEBUG){
            $tipMsg = "红包接口【".$title."】\n";
            foreach ((array)$array as $ney => $na) {
                   $tipMsg .= $ney.'：'.$na.';\n';
            }
            $tipMsg .= "时间：" .date('Y-m-d H:i:s');


            @error_log("{$tipMsg}", 3, "/var/log/debug.log");        


        }else{
            echo "not off debug!";
        } 

    }


    /**
     * curl请求
     * @param $url        请求的api
     * @param $post       是否开户post
     * @param $postFields post的数据
     * @return 接口返回的数据
     */    
    public static function curlGet($url, $post = false, $postFields = array(), $timeout = 2) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);

        if ($post && !empty($postFields)) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        }

        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }           



}



/**
 * RedpackData
 * +---------------------------------------+
 * +        红包与企业付款数据设置         +
 * +---------------------------=-----------+
 * 解析官方 xml 数据  增加set  和 get 方法
 * @author sixian
 * @version v1.0
 * @copyright  idea0086 
 * creat_time  2015-06-04 22:17 
 */
class RedpackData extends walletWeixinUtil{

    protected $values = array();

    function __construct(){
        //parent::__construct();
    }


    /*-------------------  微信红包数据  start --------------------------*/
    // 红包数据设置{{{

    public  function set_mch_billno( $mch_billno ){
        $this->values['mch_billno'] = $mch_billno;
    }
    public  function get_mch_billno(){
        try{
            return $this->values['mch_billno'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    } 

    public  function set_mch_id( $mch_id ){
        $this->values['mch_id'] = $mch_id;
    }
    public  function get_mch_id(){
        try{
            return isset($this->values['mch_id']) ? $this->values['mch_id'] : WxPayConf_pub::MCHID;
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_wxappid( $wxappid ){
        $this->values['wxappid'] = $wxappid;
    }
    public  function get_wxappid(){
        try{
            return isset($this->values['wxappid']) ? $this->values['wxappid'] : WxPayConf_pub::APPID;
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }           

    public  function set_nick_name( $nick_name ){
        $this->values['nick_name'] = $nick_name;
    }
    public  function get_nick_name(){
        try{
            return $this->values['nick_name'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_send_name( $send_name ){
        $this->values['send_name'] = $send_name;
    }
    public  function get_send_name(){
        try{
            return $this->values['send_name'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_re_openid( $re_openid ){
        $this->values['re_openid'] = $re_openid;
    }
    public  function get_re_openid(){
        try{
            return $this->values['re_openid'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_total_amount( $total_amount ){
        $this->values['total_amount'] = $total_amount;
    }
    public  function get_total_amount(){
        try{
            return $this->values['total_amount'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_amt_type( $amt_type ){
        $this->values['amt_type'] = $amt_type;
    }
    public  function get_amt_type(){
        try{
            return $this->values['amt_type'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_amt_list( $amt_list ){
        $this->values['amt_list'] = $amt_list;
    }
    public  function get_amt_list(){
        try{
            return $this->values['amt_list'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_watermark_imgurl( $watermark_imgurl ){
        $this->values['watermark_imgurl'] = $watermark_imgurl;
    }
    public  function get_watermark_imgurl(){
        try{
            return $this->values['watermark_imgurl'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_banner_imgurl( $banner_imgurl ){
        $this->values['banner_imgurl'] = $banner_imgurl;
    }
    public  function get_banner_imgurl(){
        try{
            return $this->values['banner_imgurl'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }


    public  function set_min_value( $min_value ){
        $this->values['min_value'] = $min_value;
    }
    public  function get_min_value(){
        try{
            return $this->values['min_value'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_max_value( $max_value ){
        $this->values['max_value'] = $max_value;
    }
    public  function get_max_value(){
        try{
            return $this->values['max_value'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_total_num( $total_num ){
        $this->values['total_num'] = $total_num;
    }
    public  function get_total_num(){
        try{
            return $this->values['total_num'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_wishing( $wishing ){
        $this->values['wishing'] = $wishing;
    }
    public  function get_wishing(){
        try{
            return $this->values['wishing'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_client_ip( $client_ip ){
        $this->values['client_ip'] = $client_ip;
    }
    public  function get_client_ip(){
        try{
            return $this->values['client_ip'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_act_name( $act_name ){
        $this->values['act_name'] = $act_name;
    }
    public  function get_act_name(){
        try{
            return $this->values['act_name'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_act_id( $act_id ){
        $this->values['act_id'] = $act_id;
    }
    public  function get_act_id(){
        try{
            return $this->values['act_id'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }


    public  function set_remark( $remark ){
        $this->values['remark'] = $remark;
    }
    public  function get_remark(){
        try{
            return $this->values['remark'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_logo_imgurl( $logo_imgurl ){
        $this->values['logo_imgurl'] = $logo_imgurl;
    }
    public  function get_logo_imgurl(){
        try{
            return $this->values['logo_imgurl'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }


    public  function set_share_content( $share_content ){
        $this->values['share_content'] = $share_content;    
    }
    public  function get_share_content(){
        try{
            return $this->values['share_content'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }          
    }


    public  function set_share_url( $share_url ){
        $this->values['share_url'] = $share_url;
    }
    public  function get_share_url(){
        try{
            return $this->values['share_url'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_share_imgurl( $share_imgurl ){
        $this->values['share_imgurl'] = $share_imgurl;
    }
    public  function get_share_imgurl(){
        try{
            return $this->values['share_imgurl'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_nonce_str( $nonce_str ){
        $this->values['nonce_str'] = $nonce_str;
    }
    public  function get_nonce_str(){
        try{
            return $this->values['nonce_str'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }
    // }}}
    /*-------------------  微信红包数据  end --------------------------*/    

    /*-------------------  企业付款数据  start --------------------------*/
    //红包数据设置{{{
    public  function set_mch_appid( $mch_appid ){
        $this->values['mch_appid'] = $mch_appid;
    }
    public  function get_mch_appid(){
        try{
            return isset($this->values['mch_appid']) ? $this->values['mch_appid'] : WxPayConf_pub::APPID;
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_mchid( $mchid ){
        $this->values['mchid'] = $mchid;
    }
    public  function get_mchid(){
        try{
            return isset($this->values['mchid']) ? $this->values['mchid'] : WxPayConf_pub::MCHID;
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_partner_trade_no( $partner_trade_no ){
        $this->values['partner_trade_no'] = $partner_trade_no;
    }
    public  function get_partner_trade_no(){
        try{
            return $this->values['partner_trade_no'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_openid( $openid ){
        $this->values['openid'] = $openid;
    }
    public  function get_openid(){
        try{
            return $this->values['openid'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_check_name( $check_name ){
        $this->values['check_name'] = $check_name;
    }
    public  function get_check_name(){
        try{
            return $this->values['check_name'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_re_user_name( $re_user_name ){
        $this->values['re_user_name'] = $re_user_name;
    }
    public  function get_re_user_name(){
        try{
            return $this->values['re_user_name'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_amount( $amount ){
        $this->values['amount'] = $amount;
    }
    public  function get_amount(){
        try{
            return $this->values['amount'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_desc( $desc ){
        $this->values['desc'] = $desc;
    }
    public  function get_desc(){
        try{
            return $this->values['desc'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }

    public  function set_spbill_create_ip( $spbill_create_ip ){
        $this->values['spbill_create_ip'] = $spbill_create_ip;
    }
    public  function get_spbill_create_ip(){
        try{
            return $this->values['spbill_create_ip'];
        }catch(Exception $e){
            print $e->getMessage();
            exit();
        }        
    }




    //}}}
    /*-------------------  企业付款数据  end --------------------------*/          
}




/**
 * sendWallet
 * +---------------------------------------+
 * +    红包与企业付款 官方接口与xml数据   +
 * +---------------------------------------+
 * function getSendRedpackXml    得到带有所有数据的 红包xml格式数据
 * function getSendTransfersXml  得到带有所有数据的 企业付款xml格式数据
 * @author sixian
 * @version v1.0
 * @copyright  idea0086 
 * creat_time  2015-06-04 22:17 
 */
class sendWallet extends RedpackData{

    function __construct(){
       // parent::__construct();
        $arrAuthHost = explode('|', WxPayConf_pub::OAUTH_HOST);
        if( !in_array($_SERVER['HTTP_HOST'], $arrAuthHost)){
            // 调试信息
            self:: debugErrorSendWx('host非法请求', array('referer_Host' => $_SERVER['HTTP_HOST']) );
            echo json_encode( array('code' => 0, 'msg' => 'http_host is faild!', 'ext' => array('refererHost' => $_SERVER['HTTP_HOST']) ) );
            exit;                       
        }

    }

    /**
     * 发送红包的xml数据 包
     * @param  inputObj  传入数据
     * @return 带签名的完整 xml 数据
     */    
    public  function getSendRedpackXml($inputObj){
        $xml = <<<eof
            <xml>
                <sign>{sign}</sign>
                <mch_billno>{$inputObj->get_mch_billno()}</mch_billno>
                <mch_id>{$inputObj->get_mch_id()}</mch_id>
                <wxappid>{$inputObj->get_wxappid()}</wxappid>
                <nick_name>{$inputObj->get_nick_name()}</nick_name>
                <send_name>{$inputObj->get_send_name()}</send_name>
                <re_openid>{$inputObj->get_re_openid()}</re_openid>
                <total_amount>{$inputObj->get_total_amount()}</total_amount>
                <min_value>{$inputObj->get_min_value()}</min_value>
                <max_value>{$inputObj->get_max_value()}</max_value>
                <total_num>{$inputObj->get_total_num()}</total_num>
                <wishing>{$inputObj->get_wishing()}</wishing>
                <client_ip>{$inputObj->get_client_ip()}</client_ip>
                <act_name>{$inputObj->get_act_name()}</act_name>
                <act_id>{$inputObj->get_act_id()}</act_id>
                <remark>{$inputObj->get_remark()}</remark>
                <logo_imgurl>{$inputObj->get_logo_imgurl()}</logo_imgurl>
                <share_content>{$inputObj->get_share_content()}</share_content>
                <share_url>{$inputObj->get_share_url()}</share_url>
                <share_imgurl>{$inputObj->get_share_imgurl()}</share_imgurl>
                <nonce_str>{$inputObj->get_nonce_str()}</nonce_str>
            </xml>
eof;
        $newXmlData =walletWeixinUtil:: _getSign($xml);
        $data['api_url']  = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack';
        $data['xml_data'] = $newXmlData;
        return $data;
    }

    /**
     * 发送裂变红包的xml数据 包
     * @param  inputObj  传入数据
     * @return 带签名的完整 xml 数据 add param => amt_type, amt_list, watermark_imgurl, banner_imgurl
     */    
    public  function getSendgroupredpackXml($inputObj){
        $xml = <<<eof
            <xml>
                <sign>{sign}</sign>
                <mch_billno>{$inputObj->get_mch_billno()}</mch_billno>
                <mch_id>{$inputObj->get_mch_id()}</mch_id>
                <wxappid>{$inputObj->get_wxappid()}</wxappid>
                <send_name>{$inputObj->get_send_name()}</send_name>
                <re_openid>{$inputObj->get_re_openid()}</re_openid>
                <total_amount>{$inputObj->get_total_amount()}</total_amount>
                <amt_type>{$inputObj->get_amt_type()}</amt_type>
                <amt_list>{$inputObj->get_amt_list()}</amt_list>
                <total_num>{$inputObj->get_total_num()}</total_num>
                <wishing>{$inputObj->get_wishing()}</wishing>
                <act_name>{$inputObj->get_act_name()}</act_name>
                <remark>{$inputObj->get_remark()}</remark>
                <logo_imgurl>{$inputObj->get_logo_imgurl()}</logo_imgurl>
                <share_content>{$inputObj->get_share_content()}</share_content>
                <share_url>{$inputObj->get_share_url()}</share_url>
                <nonce_str>{$inputObj->get_nonce_str()}</nonce_str>
            </xml>
eof;
            // <share_imgurl>{$inputObj->get_share_imgurl()}</share_imgurl>
            // <watermark_imgurl>{$inputObj->get_watermark_imgurl()}</watermark_imgurl>
            // <banner_imgurl>{$inputObj->get_amt_type()}</banner_imgurl>
            
        $newXmlData =walletWeixinUtil:: _getSign($xml);
        $data['api_url']  = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/sendgroupredpack';
        $data['xml_data'] = $newXmlData;
        return $data;
    }

    /**
     * 企业付款 xml 数据包
     * @param  inputObj  传入数据
     * @return 带签名的完整 xml 数据
     */
    public  function getSendTransfersXml($inputObj){
        $xml = <<<eof
            <xml>
                <mch_appid>{$inputObj->get_mch_appid()}</mch_appid>
                <mchid>{$inputObj->get_mchid()}</mchid>
                <nonce_str>{$inputObj->get_nonce_str()}</nonce_str>
                <partner_trade_no>{$inputObj->get_partner_trade_no()}</partner_trade_no>
                <openid>{$inputObj->get_openid()}</openid>
                <check_name>{$inputObj->get_check_name()}</check_name>
                <re_user_name>{$inputObj->get_re_user_name()}</re_user_name>
                <amount>{$inputObj->get_amount()}</amount>
                <desc>{$inputObj->get_desc()}!</desc>
                <spbill_create_ip>{$inputObj->get_spbill_create_ip()}</spbill_create_ip>
                <sign>{sign}</sign>
            </xml>
eof;
        $newXmlData =walletWeixinUtil:: _getSign($xml);
        $data['api_url']  = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers';
        $data['xml_data'] = $newXmlData;
        return $data;
    }


}


?>
