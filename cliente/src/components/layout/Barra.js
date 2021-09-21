import React, { useEffect, useContext} from 'react';
import AuthContext from '../../context/autenticacion/authContext';

const Barra = () => {

    // Extraer la información de autenticación
    const authContext = useContext(AuthContext);
    const { usuario, usuarioAutenticado, cerrarSesion } = authContext;

    useEffect(() => {
        usuarioAutenticado();
    }, []);

    return ( 
        <header className="app-header">
            { usuario ? <p className="nombre-usuario">!Buenos dias,  <span>{usuario.nombre}</span></p> : null }

            <nav className="nav-principal">
                <button 
                    className="btn btn-blank cerrar-sesion"
                    onClick={() => cerrarSesion()}
                >Cerrar sesión</button>

            </nav>
        </header>
     );
}
 
export default Barra;