//
//  ViewController.m
//  HookStaticMethod
//
//  Created by Qu,Ke on 2020/4/16.
//  Copyright © 2020 baidu. All rights reserved.
//

#import "ViewController.h"
#include "staticHook.h"
 
void mytest(void){
    NSLog(@"test method is call \n");
}


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    
    [super viewDidLoad];
//    mytest();
    searchStaticMethodForName("mytest");
    
}

@end
