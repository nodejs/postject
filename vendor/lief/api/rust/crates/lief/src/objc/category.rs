use lief_ffi as ffi;

use super::{DeclOpt, Method, Property, Protocol};
use crate::common::FromFFI;
use crate::declare_fwd_iterator;
use std::marker::PhantomData;

/// This class represents an Objective-C category (e.g.
/// `@interface NSString (MyAdditions)`)
pub struct Category<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Category>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Category> for Category<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Category>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData,
        }
    }
}

impl Category<'_> {
    /// Name of the category
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// (demangled) name of the class extended by this category
    pub fn class_name(&self) -> String {
        self.ptr.class_name().to_string()
    }

    /// Iterator over the different [`Method`] defined by this category
    pub fn methods(&self) -> Methods<'_> {
        Methods::new(self.ptr.methods())
    }

    /// Iterator over the different [`Protocol`] adopted by this category
    pub fn protocols(&self) -> Protocols<'_> {
        Protocols::new(self.ptr.protocols())
    }

    /// Iterator over the [`Property`] of this category
    pub fn properties(&self) -> Properties<'_> {
        Properties::new(self.ptr.properties())
    }

    /// Generate a header-like string for this specific category
    pub fn to_decl(&self) -> String {
        self.ptr.to_decl().to_string()
    }

    /// Same behavior as [`Category::to_decl`] but with an additional
    /// [`DeclOpt`] parameter to customize the output
    pub fn to_decl_with_opt(&self, opt: &DeclOpt) -> String {
        self.ptr.to_decl_with_opt(&opt.to_ffi()).to_string()
    }
}

declare_fwd_iterator!(
    Methods,
    Method<'a>,
    ffi::ObjC_Method,
    ffi::ObjC_Category,
    ffi::ObjC_Category_it_methods
);

declare_fwd_iterator!(
    Protocols,
    Protocol<'a>,
    ffi::ObjC_Protocol,
    ffi::ObjC_Category,
    ffi::ObjC_Category_it_protocols
);

declare_fwd_iterator!(
    Properties,
    Property<'a>,
    ffi::ObjC_Property,
    ffi::ObjC_Category,
    ffi::ObjC_Category_it_properties
);
